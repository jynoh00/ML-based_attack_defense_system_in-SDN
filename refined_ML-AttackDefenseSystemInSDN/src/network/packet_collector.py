#!/usr/bin/env python3

import numpy as np
import pandas as pd
import joblib
import time
from collections import defaultdict, deque
from datetime import datetime
import logging
import sys
import os

sys.path.append(os.path.dirname(__file__))
from feature_mapper import FeatureMapper

class PacketCollector:
    def __init__(self, ml_model_path, scaler_path=None, encoders_path=None,
                 window_size=10, attack_threshold=0.7):  # window 10초
        """
        실시간 패킷 수집 및 공격 탐지
        - 짧은 시간 윈도우로 빠른 탐지
        - IP 기반 행동 분석 강화
        """
        self.logger = logging.getLogger(__name__)
       
        # ML 모델 로드
        try:
            self.model = joblib.load(ml_model_path)
            self.model_feature_names = None
           
            if hasattr(self.model, 'feature_names_in_'):
                self.model_feature_names = self.model.feature_names_in_
                self.logger.info(f"ML model loaded with {len(self.model_feature_names)} features")
            else:
                self.logger.warning(f"ML model loaded but feature names not available")
           
            self.use_ml = True
           
        except Exception as e:
            self.logger.error(f"Failed to load ML model: {e}")
            self.model = None
            self.use_ml = False
       
        # 스케일러 로드
        self.scaler = None
        if scaler_path and os.path.exists(scaler_path):
            try:
                self.scaler = joblib.load(scaler_path)
                self.logger.info(f"Scaler loaded: {scaler_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load scaler: {e}")
       
        self.feature_mapper = FeatureMapper()
        self.window_size = window_size
       
        # 플로우 캐시 (5-tuple)
        self.flows = defaultdict(list)
       
        # 패킷 윈도우
        self.packet_window = deque(maxlen=10000)
       
        self.ip_behavior = defaultdict(lambda: {
            'packets': deque(maxlen=1000),
            'dst_ports': set(),
            'dst_ips': set(),
            'syn_count': 0,
            'total_count': 0,
            'first_seen': 0,
            'last_seen': 0,
            'suspicious_score': 0
        })
       
        # 통계
        self.stats = {
            'total_packets': 0,
            'total_attacks': 0,
            'attacks_by_type': defaultdict(int),
            'ml_predictions': 0,
            'heuristic_predictions': 0
        }
       
        # 임계값
        self.attack_threshold = attack_threshold
        self.logger.info(f"Attack detection threshold: {self.attack_threshold:.2%}")
        self.logger.info(f"Window size: {self.window_size}s")
       
        self.enable_heuristic_fallback = True

    def analyze_packet(self, packet_info):
        """패킷 분석 - 실시간 최적화 버전"""
        self.stats['total_packets'] += 1
       
        packet_info['timestamp'] = time.time()
        self.packet_window.append(packet_info)
       
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return False, None, 0.0
       
        # IP 행동 업데이트
        self._update_ip_behavior(src_ip, packet_info)
       
        heuristic_result = self._realtime_heuristic_check(src_ip, packet_info)
        if heuristic_result[0]:  # 공격 탐지됨
            self.stats['total_attacks'] += 1
            self.stats['attacks_by_type'][heuristic_result[1]] += 1
            return heuristic_result
       
        flow_key = self._get_flow_key(packet_info)
        self.flows[flow_key].append(packet_info)
        flow_packets = self.flows[flow_key]
       
        if self.use_ml and len(flow_packets) >= 5:
            try:
                is_attack, attack_type, confidence = self._ml_prediction(packet_info, flow_key)
                self.stats['ml_predictions'] += 1
               
                if is_attack:
                    self.stats['total_attacks'] += 1
                    self.stats['attacks_by_type'][attack_type] += 1
                    self.logger.info(
                        f"ML detected {attack_type}: conf={confidence:.2%}, "
                        f"flow_pkts={len(flow_packets)}"
                    )
                    return True, attack_type, confidence
                   
            except Exception as e:
                self.logger.debug(f"ML failed: {e}")
       
        return False, None, 0.0

    def _update_ip_behavior(self, src_ip, packet_info):
        """IP 행동 추적 업데이트"""
        behavior = self.ip_behavior[src_ip]
        current_time = time.time()
       
        if behavior['first_seen'] == 0:
            behavior['first_seen'] = current_time
        behavior['last_seen'] = current_time
       
        behavior['packets'].append(packet_info)
        behavior['total_count'] += 1
       
        dst_port = packet_info.get('dst_port', 0)
        dst_ip = packet_info.get('dst_ip')
       
        if dst_port > 0:
            behavior['dst_ports'].add(dst_port)
        if dst_ip:
            behavior['dst_ips'].add(dst_ip)
       
        tcp_flags = packet_info.get('tcp_flags', 0)
        if tcp_flags & 0x02:  # SYN
            behavior['syn_count'] += 1

    def _realtime_heuristic_check(self, src_ip, packet_info):
        """실시간 휴리스틱 탐지"""
        self.stats['heuristic_predictions'] += 1
       
        behavior = self.ip_behavior[src_ip]
        current_time = time.time()
       
        window_start = current_time - self.window_size
        recent_packets = [p for p in behavior['packets']
                         if p.get('timestamp', 0) >= window_start]
       
        if len(recent_packets) < 3:
            return False, None, 0.0
       
        time_span = current_time - behavior['first_seen']
        if time_span <= 0:
            time_span = 0.001
       
        # 1. PORT SCAN 탐지
        unique_ports = len(behavior['dst_ports'])
        if unique_ports >= 8: 
            confidence = min(0.95, 0.7 + (unique_ports / 100))
            self.logger.warning(
                f"🔍 Port Scan detected: {src_ip} scanned {unique_ports} ports "
                f"in {time_span:.1f}s"
            )
            return True, 'PortScan', confidence
       
        # 2. SYN FLOOD 탐지
        if len(recent_packets) >= 10:
            syn_ratio = behavior['syn_count'] / behavior['total_count']
            if syn_ratio >= 0.3:  # 0.4 -> 0.3
                confidence = min(0.95, 0.6 + syn_ratio * 0.5)
                self.logger.warning(
                    f"🔍 SYN Flood detected: {src_ip} SYN ratio={syn_ratio:.1%} "
                    f"({behavior['syn_count']}/{behavior['total_count']})"
                )
                return True, 'SYN_Flood', confidence
       
        # 3. HIGH RATE 공격
        if len(recent_packets) >= 20:
            recent_time_span = current_time - recent_packets[0].get('timestamp', current_time)
            if recent_time_span > 0:
                pps = len(recent_packets) / recent_time_span
                if pps > 30:
                    confidence = min(0.95, 0.5 + (pps / 200))
                    self.logger.warning(
                        f"🔍 High Rate detected: {src_ip} sending {pps:.0f} pps"
                    )
                    return True, 'HighRate_DDoS', confidence
       
        # 4. ICMP FLOOD (Ping Flood)
        icmp_count = sum(1 for p in recent_packets if p.get('protocol') == 1)
        if icmp_count >= 15: 
            icmp_ratio = icmp_count / len(recent_packets)
            if icmp_ratio > 0.5:
                confidence = min(0.95, 0.6 + icmp_ratio * 0.3)
                self.logger.warning(
                    f"🔍 ICMP Flood detected: {src_ip} sent {icmp_count} ICMP packets"
                )
                return True, 'ICMP_Flood', confidence
       
        # 5. 단일 타겟 집중 공격
        if len(behavior['dst_ips']) == 1 and len(recent_packets) >= 15:
            target = list(behavior['dst_ips'])[0]
            confidence = 0.70
            self.logger.warning(
                f"🔍 Focused attack detected: {src_ip} -> {target} "
                f"({len(recent_packets)} packets)"
            )
            return True, 'Focused_Attack', confidence
       
        return False, None, 0.0

    def _ml_prediction(self, packet_info, flow_key):
        """ML 모델 예측 (보조)"""
        flow_packets = self.flows[flow_key]
       
        # 특징 추출
        cicids_features = self.feature_mapper.extract_features(packet_info, flow_packets)
       
        # DataFrame 변환
        if self.model_feature_names is not None:
            feature_df = self.feature_mapper.to_dataframe(cicids_features, self.model_feature_names)
        else:
            feature_df = self.feature_mapper.to_dataframe(cicids_features)
       
        # 누락 특징 처리
        if self.model_feature_names is not None:
            for col in self.model_feature_names:
                if col not in feature_df.columns:
                    feature_df[col] = 0
            feature_df = feature_df[self.model_feature_names]
       
        # NaN/Inf 처리
        feature_df = feature_df.replace([np.inf, -np.inf], 0)
        feature_df = feature_df.fillna(0)
       
        # 스케일링
        if self.scaler:
            try:
                feature_df = pd.DataFrame(
                    self.scaler.transform(feature_df),
                    columns=feature_df.columns
                )
            except Exception as e:
                self.logger.debug(f"Scaling failed: {e}")
       
        # 예측
        prediction = self.model.predict(feature_df)[0]
       
        # 확률
        if hasattr(self.model, 'predict_proba'):
            proba = self.model.predict_proba(feature_df)[0]
            confidence = np.max(proba)
        else:
            confidence = 1.0 if prediction == 1 else 0.0
       
        is_attack = bool(prediction == 1)
       
        if is_attack and confidence >= self.attack_threshold:
            attack_type = self._classify_attack_type(packet_info, cicids_features)
            return True, attack_type, confidence
       
        return False, None, confidence

    def _get_flow_key(self, packet_info):
        """플로우 키 생성"""
        return (
            packet_info.get('src_ip', '0.0.0.0'),
            packet_info.get('dst_ip', '0.0.0.0'),
            packet_info.get('src_port', 0),
            packet_info.get('dst_port', 0),
            packet_info.get('protocol', 0)
        )

    def _classify_attack_type(self, packet_info, features):
        """공격 유형 분류"""
        src_ip = packet_info.get('src_ip')
        behavior = self.ip_behavior.get(src_ip)
       
        if behavior:
            # 행동 기반 분류
            if len(behavior['dst_ports']) > 10:
                return 'PortScan'
           
            syn_ratio = behavior['syn_count'] / max(behavior['total_count'], 1)
            if syn_ratio > 0.5:
                return 'SYN_Flood'
       
        # 특징 기반 분류
        dst_port = packet_info.get('dst_port', 0)
       
        if dst_port in [80, 443, 8080]:
            return 'Web_Attack'
        elif dst_port == 22:
            return 'SSH_Attack'
        elif packet_info.get('protocol') == 1:
            return 'ICMP_Flood'
       
        return 'Unknown_Attack'

    def cleanup_old_flows(self, max_age=300):
        """오래된 데이터 정리"""
        current_time = time.time()
       
        # 플로우 정리
        flows_to_delete = []
        for flow_key, packets in self.flows.items():
            if packets and (current_time - packets[-1]['timestamp']) > max_age:
                flows_to_delete.append(flow_key)
       
        for flow_key in flows_to_delete:
            del self.flows[flow_key]
       
        # IP 행동 정리
        ips_to_delete = []
        for ip, behavior in self.ip_behavior.items():
            if (current_time - behavior['last_seen']) > max_age:
                ips_to_delete.append(ip)
       
        for ip in ips_to_delete:
            del self.ip_behavior[ip]
       
        if flows_to_delete or ips_to_delete:
            self.logger.info(
                f"Cleaned up {len(flows_to_delete)} flows, "
                f"{len(ips_to_delete)} IP behaviors"
            )

    def get_statistics(self):
        """통계 정보"""
        return {
            'total_packets': self.stats['total_packets'],
            'total_attacks': self.stats['total_attacks'],
            'attack_rate': self.stats['total_attacks'] / max(self.stats['total_packets'], 1),
            'attacks_by_type': dict(self.stats['attacks_by_type']),
            'active_flows': len(self.flows),
            'tracked_ips': len(self.ip_behavior),
            'window_packets': len(self.packet_window),
            'ml_predictions': self.stats['ml_predictions'],
            'heuristic_predictions': self.stats['heuristic_predictions'],
            'using_ml': self.use_ml,
            'attack_threshold': self.attack_threshold
        }
   
    def get_ip_behavior_summary(self):
        """IP 행동 요약 (디버깅용)"""
        summary = {}
        for ip, behavior in self.ip_behavior.items():
            summary[ip] = {
                'total_packets': behavior['total_count'],
                'unique_ports': len(behavior['dst_ports']),
                'unique_targets': len(behavior['dst_ips']),
                'syn_ratio': behavior['syn_count'] / max(behavior['total_count'], 1),
                'duration': behavior['last_seen'] - behavior['first_seen']
            }
        return summary