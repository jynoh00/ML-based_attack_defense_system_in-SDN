#!/usr/bin/env python3

"""
CICIDS2017 특징 매핑 (개선 버전)
실시간 패킷 정보를 ML 모델이 기대하는 특징으로 변환
"""

import numpy as np
import pandas as pd
from collections import defaultdict
import time

class FeatureMapper:
    """실시간 패킷에서 CICIDS2017 특징 추출"""
   
    # CICIDS2017 데이터셋의 표준 특징 이름들
    CICIDS_FEATURES = [
        'Destination Port',
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Bwd Packet Length Std',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Flow IAT Mean',
        'Flow IAT Std',
        'Flow IAT Max',
        'Flow IAT Min',
        'Fwd IAT Total',
        'Fwd IAT Mean',
        'Fwd IAT Std',
        'Fwd IAT Max',
        'Fwd IAT Min',
        'Bwd IAT Total',
        'Bwd IAT Mean',
        'Bwd IAT Std',
        'Bwd IAT Max',
        'Bwd IAT Min',
        'Fwd PSH Flags',
        'Bwd PSH Flags',
        'Fwd URG Flags',
        'Bwd URG Flags',
        'Fwd Header Length',
        'Bwd Header Length',
        'Fwd Packets/s',
        'Bwd Packets/s',
        'Min Packet Length',
        'Max Packet Length',
        'Packet Length Mean',
        'Packet Length Std',
        'Packet Length Variance',
        'FIN Flag Count',
        'SYN Flag Count',
        'RST Flag Count',
        'PSH Flag Count',
        'ACK Flag Count',
        'URG Flag Count',
        'CWE Flag Count',
        'ECE Flag Count',
        'Down/Up Ratio',
        'Average Packet Size',
        'Avg Fwd Segment Size',
        'Avg Bwd Segment Size',
        'Fwd Header Length.1',
        'Fwd Avg Bytes/Bulk',
        'Fwd Avg Packets/Bulk',
        'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk',
        'Bwd Avg Packets/Bulk',
        'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets',
        'Subflow Fwd Bytes',
        'Subflow Bwd Packets',
        'Subflow Bwd Bytes',
        'Init_Win_bytes_forward',
        'Init_Win_bytes_backward',
        'act_data_pkt_fwd',
        'min_seg_size_forward',
        'Active Mean',
        'Active Std',
        'Active Max',
        'Active Min',
        'Idle Mean',
        'Idle Std',
        'Idle Max',
        'Idle Min',
    ]
   
    def __init__(self):
        # 플로우 방향 정의를 위한 기준 저장
        self.flow_directions = {}
   
    def extract_features(self, packet_info, flow_packets):
        """
        패킷 정보에서 CICIDS2017 특징 추출
       
        Args:
            packet_info: 현재 패킷 정보
            flow_packets: 해당 플로우의 모든 패킷 리스트
       
        Returns:
            dict: CICIDS2017 특징 딕셔너리
        """
        if not flow_packets:
            return self._get_default_features()
       
        # 플로우 방향 결정 (첫 패킷 기준)
        flow_key = self._get_flow_key(packet_info)
        if flow_key not in self.flow_directions:
            self.flow_directions[flow_key] = {
                'src_ip': flow_packets[0].get('src_ip'),
                'dst_ip': flow_packets[0].get('dst_ip'),
                'src_port': flow_packets[0].get('src_port'),
                'dst_port': flow_packets[0].get('dst_port')
            }
       
        flow_dir = self.flow_directions[flow_key]
       
        # Forward/Backward 패킷 분류
        fwd_packets = []
        bwd_packets = []
        fwd_flags = defaultdict(int)
        bwd_flags = defaultdict(int)
       
        for pkt in flow_packets:
            is_forward = (pkt.get('src_ip') == flow_dir['src_ip'] and
                         pkt.get('dst_ip') == flow_dir['dst_ip'])
           
            if is_forward:
                fwd_packets.append(pkt)
                self._count_flags(pkt, fwd_flags)
            else:
                bwd_packets.append(pkt)
                self._count_flags(pkt, bwd_flags)
       
        # 특징 계산
        features = {}
       
        # 기본 정보
        features['Destination Port'] = flow_dir['dst_port']
       
        # 플로우 지속 시간 (microseconds)
        if len(flow_packets) > 1:
            flow_duration = (flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp']) * 1_000_000
        else:
            flow_duration = 1  # 0으로 나누기 방지
        features['Flow Duration'] = max(flow_duration, 1)
       
        # 패킷 수
        features['Total Fwd Packets'] = len(fwd_packets)
        features['Total Backward Packets'] = len(bwd_packets)
       
        # 패킷 길이 추출
        fwd_lengths = [p.get('packet_size', 0) for p in fwd_packets]
        bwd_lengths = [p.get('packet_size', 0) for p in bwd_packets]
        all_lengths = fwd_lengths + bwd_lengths
       
        # 총 길이
        features['Total Length of Fwd Packets'] = sum(fwd_lengths)
        features['Total Length of Bwd Packets'] = sum(bwd_lengths)
       
        # Forward 패킷 길이 통계
        if fwd_lengths:
            features['Fwd Packet Length Max'] = max(fwd_lengths)
            features['Fwd Packet Length Min'] = min(fwd_lengths)
            features['Fwd Packet Length Mean'] = np.mean(fwd_lengths)
            features['Fwd Packet Length Std'] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
        else:
            features['Fwd Packet Length Max'] = 0
            features['Fwd Packet Length Min'] = 0
            features['Fwd Packet Length Mean'] = 0
            features['Fwd Packet Length Std'] = 0
       
        # Backward 패킷 길이 통계
        if bwd_lengths:
            features['Bwd Packet Length Max'] = max(bwd_lengths)
            features['Bwd Packet Length Min'] = min(bwd_lengths)
            features['Bwd Packet Length Mean'] = np.mean(bwd_lengths)
            features['Bwd Packet Length Std'] = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
        else:
            features['Bwd Packet Length Max'] = 0
            features['Bwd Packet Length Min'] = 0
            features['Bwd Packet Length Mean'] = 0
            features['Bwd Packet Length Std'] = 0
       
        # 플로우 통계
        total_bytes = sum(all_lengths)
        total_packets = len(flow_packets)
        flow_duration_sec = flow_duration / 1_000_000
       
        if flow_duration_sec > 0:
            features['Flow Bytes/s'] = total_bytes / flow_duration_sec
            features['Flow Packets/s'] = total_packets / flow_duration_sec
            features['Fwd Packets/s'] = len(fwd_packets) / flow_duration_sec
            features['Bwd Packets/s'] = len(bwd_packets) / flow_duration_sec
        else:
            features['Flow Bytes/s'] = 0
            features['Flow Packets/s'] = 0
            features['Fwd Packets/s'] = 0
            features['Bwd Packets/s'] = 0
       
        # IAT (Inter-Arrival Time) 계산
        iat_features = self._calculate_iat(flow_packets, fwd_packets, bwd_packets)
        features.update(iat_features)
       
        # TCP 플래그
        flag_features = self._get_flag_features(fwd_flags, bwd_flags)
        features.update(flag_features)
       
        # PSH/URG 플래그 (Forward/Backward 구분)
        features['Fwd PSH Flags'] = fwd_flags['PSH']
        features['Bwd PSH Flags'] = bwd_flags['PSH']
        features['Fwd URG Flags'] = fwd_flags['URG']
        features['Bwd URG Flags'] = bwd_flags['URG']
       
        # 헤더 길이 추정
        protocol = packet_info.get('protocol', 6)
        header_len = 40 if protocol == 6 else 28  # TCP(20+20) or UDP(8+20)
       
        features['Fwd Header Length'] = len(fwd_packets) * header_len
        features['Bwd Header Length'] = len(bwd_packets) * header_len
        features['Fwd Header Length.1'] = features['Fwd Header Length']
       
        # 패킷 길이 통계
        if all_lengths:
            features['Min Packet Length'] = min(all_lengths)
            features['Max Packet Length'] = max(all_lengths)
            features['Packet Length Mean'] = np.mean(all_lengths)
            features['Packet Length Std'] = np.std(all_lengths) if len(all_lengths) > 1 else 0
            features['Packet Length Variance'] = np.var(all_lengths) if len(all_lengths) > 1 else 0
        else:
            features['Min Packet Length'] = 0
            features['Max Packet Length'] = 0
            features['Packet Length Mean'] = 0
            features['Packet Length Std'] = 0
            features['Packet Length Variance'] = 0
       
        # Down/Up Ratio
        features['Down/Up Ratio'] = len(bwd_packets) / len(fwd_packets) if len(fwd_packets) > 0 else 0
       
        # 평균 패킷 크기
        features['Average Packet Size'] = np.mean(all_lengths) if all_lengths else 0
        features['Avg Fwd Segment Size'] = np.mean(fwd_lengths) if fwd_lengths else 0
        features['Avg Bwd Segment Size'] = np.mean(bwd_lengths) if bwd_lengths else 0
       
        # Bulk 전송 특징 (실시간에서는 계산 어려움, 0으로 설정)
        features['Fwd Avg Bytes/Bulk'] = 0
        features['Fwd Avg Packets/Bulk'] = 0
        features['Fwd Avg Bulk Rate'] = 0
        features['Bwd Avg Bytes/Bulk'] = 0
        features['Bwd Avg Packets/Bulk'] = 0
        features['Bwd Avg Bulk Rate'] = 0
       
        # Subflow (전체 플로우를 subflow로 취급)
        features['Subflow Fwd Packets'] = len(fwd_packets)
        features['Subflow Fwd Bytes'] = sum(fwd_lengths)
        features['Subflow Bwd Packets'] = len(bwd_packets)
        features['Subflow Bwd Bytes'] = sum(bwd_lengths)
       
        # TCP 윈도우 크기 (기본값)
        features['Init_Win_bytes_forward'] = 8192
        features['Init_Win_bytes_backward'] = 8192
       
        # Active 데이터 패킷
        features['act_data_pkt_fwd'] = len([p for p in fwd_packets if p.get('packet_size', 0) > header_len])
        features['min_seg_size_forward'] = 20  # TCP 최소 헤더
       
        # Active/Idle 시간 (실시간 계산 복잡, 0으로 설정)
        features['Active Mean'] = 0
        features['Active Std'] = 0
        features['Active Max'] = 0
        features['Active Min'] = 0
        features['Idle Mean'] = 0
        features['Idle Std'] = 0
        features['Idle Max'] = 0
        features['Idle Min'] = 0
       
        # NaN/Inf 체크 및 처리
        for key in features:
            if not np.isfinite(features[key]):
                features[key] = 0
       
        return features
   
    def _get_flow_key(self, packet_info):
        """플로우 키 생성 (양방향 고려)"""
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol', 0)
       
        # 정렬하여 양방향 플로우를 같은 키로 매핑
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
   
    def _count_flags(self, packet, flag_counter):
        """TCP 플래그 카운트"""
        tcp_flags = packet.get('tcp_flags', 0)
        if tcp_flags & 0x01: flag_counter['FIN'] += 1
        if tcp_flags & 0x02: flag_counter['SYN'] += 1
        if tcp_flags & 0x04: flag_counter['RST'] += 1
        if tcp_flags & 0x08: flag_counter['PSH'] += 1
        if tcp_flags & 0x10: flag_counter['ACK'] += 1
        if tcp_flags & 0x20: flag_counter['URG'] += 1
        if tcp_flags & 0x80: flag_counter['CWE'] += 1
        if tcp_flags & 0x40: flag_counter['ECE'] += 1
   
    def _get_flag_features(self, fwd_flags, bwd_flags):
        """플래그 특징 생성"""
        return {
            'FIN Flag Count': fwd_flags['FIN'] + bwd_flags['FIN'],
            'SYN Flag Count': fwd_flags['SYN'] + bwd_flags['SYN'],
            'RST Flag Count': fwd_flags['RST'] + bwd_flags['RST'],
            'PSH Flag Count': fwd_flags['PSH'] + bwd_flags['PSH'],
            'ACK Flag Count': fwd_flags['ACK'] + bwd_flags['ACK'],
            'URG Flag Count': fwd_flags['URG'] + bwd_flags['URG'],
            'CWE Flag Count': fwd_flags['CWE'] + bwd_flags['CWE'],
            'ECE Flag Count': fwd_flags['ECE'] + bwd_flags['ECE'],
        }
   
    def _calculate_iat(self, flow_packets, fwd_packets, bwd_packets):
        """Inter-Arrival Time 계산"""
        features = {}
       
        # 전체 플로우 IAT
        if len(flow_packets) > 1:
            iats = [(flow_packets[i]['timestamp'] - flow_packets[i-1]['timestamp']) * 1_000_000
                    for i in range(1, len(flow_packets))]
            features['Flow IAT Mean'] = np.mean(iats)
            features['Flow IAT Std'] = np.std(iats) if len(iats) > 1 else 0
            features['Flow IAT Max'] = max(iats)
            features['Flow IAT Min'] = min(iats)
        else:
            features['Flow IAT Mean'] = 0
            features['Flow IAT Std'] = 0
            features['Flow IAT Max'] = 0
            features['Flow IAT Min'] = 0
       
        # Forward IAT
        if len(fwd_packets) > 1:
            fwd_iats = [(fwd_packets[i]['timestamp'] - fwd_packets[i-1]['timestamp']) * 1_000_000
                        for i in range(1, len(fwd_packets))]
            features['Fwd IAT Total'] = sum(fwd_iats)
            features['Fwd IAT Mean'] = np.mean(fwd_iats)
            features['Fwd IAT Std'] = np.std(fwd_iats) if len(fwd_iats) > 1 else 0
            features['Fwd IAT Max'] = max(fwd_iats)
            features['Fwd IAT Min'] = min(fwd_iats)
        else:
            features['Fwd IAT Total'] = 0
            features['Fwd IAT Mean'] = 0
            features['Fwd IAT Std'] = 0
            features['Fwd IAT Max'] = 0
            features['Fwd IAT Min'] = 0
       
        # Backward IAT
        if len(bwd_packets) > 1:
            bwd_iats = [(bwd_packets[i]['timestamp'] - bwd_packets[i-1]['timestamp']) * 1_000_000
                        for i in range(1, len(bwd_packets))]
            features['Bwd IAT Total'] = sum(bwd_iats)
            features['Bwd IAT Mean'] = np.mean(bwd_iats)
            features['Bwd IAT Std'] = np.std(bwd_iats) if len(bwd_iats) > 1 else 0
            features['Bwd IAT Max'] = max(bwd_iats)
            features['Bwd IAT Min'] = min(bwd_iats)
        else:
            features['Bwd IAT Total'] = 0
            features['Bwd IAT Mean'] = 0
            features['Bwd IAT Std'] = 0
            features['Bwd IAT Max'] = 0
            features['Bwd IAT Min'] = 0
       
        return features
   
    def _get_default_features(self):
        """기본 특징 반환 (첫 패킷)"""
        return {feature: 0 for feature in self.CICIDS_FEATURES}
   
    def to_dataframe(self, features, feature_names=None):
        """
        특징을 DataFrame으로 변환
       
        Args:
            features: 추출한 특징 딕셔너리
            feature_names: 모델이 기대하는 특징 이름 순서
       
        Returns:
            pd.DataFrame: 모델 입력용 DataFrame
        """
        if feature_names is None:
            feature_names = self.CICIDS_FEATURES
       
        # 모델이 기대하는 순서대로 특징 정렬
        ordered_features = {}
        for name in feature_names:
            ordered_features[name] = features.get(name, 0)
       
        return pd.DataFrame([ordered_features])