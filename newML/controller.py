#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp
from ryu.lib import hub

import time
import json
import numpy as np
import pandas as pd
import joblib
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
import os

import sys
sys.path.append('src/ml_models')
sys.path.append('src/utils')

try:
    from feature_extraction import NetworkFeatureExtractor
    from config import MLDefenseConfig
    from logger import setup_logger
except ImportError: print('Warning: Custom modules not found. Some features may be limited.')

class MLDefenseController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MLDefenseController, self).__init__(*args, **kwargs) # app_manager.RyuApp 상속

        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.datapaths = {}

        self.packet_buffer = deque(maxlen=10000) # 패킷 버퍼는 덱 구조로
        self.flow_cache = defaultdict(list) # 플로우 캐시 정보는 리스트 값 딕셔너리
        self.connection_tracker = defaultdict(lambda: deque(maxlen=1000))

        self.ml_models = {}
        self.feature_extractor = NetworkFeatureExtractor()
        self.prediction_cache = {}
        self.model_update_interval = 300 # 300s = 5m

        self.blocked_ips = set()
        self.suspicious_ips = defaultdict(float) # float = 의심 점수, 딕셔너리
        self.attack_counters = defaultdict(int)
        self.whiteList_ips = {'10.0.1.250'} # Monitor - *** topo에서 10.30.1.20/24로 설정했었음, 수정 필요

        self.config = {
            'model_path': 'data/models/',
            'detection_threshold': 0.7,
            'block_duration': 300, #5m
            'max_suspicious_score': 100.0,
            'feature_window': 60,
            'batch_prediction_size': 100,
            'log_level': 'INFO'
        }

        self.performance_stats = {
            'packet_processed': 0,
            'attack_detected': 0,
            'false_positives': 0,
            'blocked_connections': 0,
            'prediction_time_avg': 0.0,
            'model_accuracy': 0.0
        }

        # about thread
        self.prediction_thread = None
        self.cleanup_thread = None
        self.stats_thread = None
        self.ruunning = True

        self.setup_logging()
        self.load_ml_models()
        self.start_background_tasks()

        self.logger.info('ML Defense Controller initialized')

    def setup_logging(self): 
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=getattr(logging, self.config['log_level']), format=log_format)
        self.logger = logging.getLogger('MLDefenseController')

        # file handler
        os.makedirs('logs', exist_ok=True)
        file_handler = logging.FileHandler('logs/ml_defense.log')
        file_handler.setFormatter(logging.Formatter(log_format))
        self.logger.addHandler(file_handler)

    def load_ml_models(self): 
        self.logger.info('Loading ML models ...')

        model_types = ['random_forest', 'svm', 'neural_network', 'ensemble']
        datasets = ['cicids2017', 'nslkdd']
        
        for dataset in datasets:
            for model_type in model_types:
                model_path = os.path.join(self.config['model_path'], f'{dataset}_{model_type}')

                if os.path.exists(model_path):
                    try:
                        model_file = os.path.join(model_path, 'model.pkl')
                        if os.path.exists(model_file):
                            model = joblib.load(model_file)

                            scaler_file = os.path.join(model_path, 'scaler.pkl')
                            encoder_file = os.path.join(model_path, 'encoders.pkl')

                            scaler = joblib.load(scaler_file) if os.path.exists(scaler_file) else None
                            encoders = joblib.load(encoder_file) if os.path.exists(encoder_file) else None

                            self.ml_models[f'{dataset}_{model_type}'] = {
                                'model': model,
                                'scaler': scaler,
                                'encoders': encoders,
                                'dataset': dataset,
                                'type': model_type
                            }

                            self.logger.info(f'Loaded model: {dataset}_{model_type}')
                    except Exception as e: self.logger.error(f'Error loading model {dataset}_{model_type}: {e}')

        if not self.ml_models: self.logger.warning('No ML models loaded. Using rule-based detection only')
        else: self.logger.info(f'Loaded {len(self.ml_models)} ML models successfully')

    def start_background_tasks(self): # 3개의 추가 그린스레드 생성
        self.prediction_thread = hub.spawn(self.prediction_worker) # Ryu 프레임워크 내 경량 스레드 (green thread) 생성 함수 : hub.spawn()
        self.cleanup_thread = hub.spawn(self.cleanup_worker) # 인자로 넘긴 None들에 hub.GreenThread 객체가 들어간다
        self.stats_thread = hub.spawn(self.stats_worker)

        self.logger.info('Background tasks started')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev): 
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath # datapath id - datapath, key-value

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info(f'Switch {datapath.id} connected')

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match,
                instructions=inst, idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    def block_ip(self, src_ip, duration=None): 
        if src_ip in self.whiteList_ips: self.logger.warning(f'Attempted to block whitelisted IP: {src_ip}'); return

        if duration is None: duration = self.config['block_duration']

        self.blocked_ips.add(src_ip)
        self.performance_stats['blocked_connections'] += 1

        for datapath in self.datapaths.values():
            match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            actions = []

            self.add_flow(datapath, 1000, match, actions, hard_timeout=duration)

        self.logger.warning(f'BLOCKED IP: {src_ip} for {duration} seconds')
        # duration 동안 해당 ip address 차단, 이후 언블락
        hub.spawn_after(duration, self.unblock_ip, src_ip) # Duration 이후 self.unblock_ip() 실행 - src_ip 인자로

    def unblock_ip(self, src_ip): 
        if src_ip in self.blocked_ips:
            self.blocked_ips.remove(src_ip)
            self.logger.info(f'UNBLOCKED IP: {src_ip}')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATHER)
    def packet_in_handler(self, ev): 
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt: self.handle_non_ip_packet(ev); return

        packet_info = self.extract_packet_info(pkt, in_port, time.time())
        self.performance_stats['packets_processed'] += 1

        if packet_info['src_ip'] in self.blocked_ips:
            self.logger.debug(f'Dropped packet from blocked IP: {packet_info['src_ip']}')
            return

        self.packet_buffer.append(packet_info)
        self.update_connection_tracking(packet_info)
        threat_detected = self.rule_based_detection(packet_info)

        if threat_detected:
            self.handle_threat(packet_info, 'rule_based', threat_detected)
            return

        self.forward_packet(ev, packet_info)

    def extract_packet_info(self, pkt, in_port, timestamp):
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        packet_info = {
            'timestamp': timestamp,
            'in_port': in_port,
            'src_mac': eth.src,
            'dst_mac': eth.dst,
            'src_ip': ip_pkt.src,
            'dst_ip': ip_pkt.dst,
            'protocol': ip_pkt.proto,
            'packet_size': len(pkt.data),
            'src_port': 0,
            'dst_port': 0,
            'tcp_flags': 0
        }

        if ip_pkt.proto == 6: # TCP
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                packet_info['src_port'] = tcp_pkt.src_port
                packet_info['dst_port'] = tcp_pkt.dst_port
                packet_info['tcp_flags'] = tcp_pkt.bits
        
        elif ip_pkt.proto == 17: # UDP
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt:
                packet_info['src_port'] = udp_pkt.src_port
                packet_info['dst_port'] = udp_pkt.dst_port
        
        return packet_info
        
    def update_connection_tracking(self, packet_info): # flow_cache, connection_tracker 업데이트
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']

        connection_key = f'{src_ip}:{packet_info['src_port']}->{dst_ip}:{packet_info['dst_port']}'
        self.connection_tracker[src_ip].append(packet_info['timestamp'])

        flow_key = f'{src_ip}->{dst_ip}'
        self.flow_cache[flow_key].append(packet_info) # flow_key - packet_info, key-value

        if len(self.flow_cache[flow_key]) > 100: self.flow_cache[flow_key] = self.flow_cache[flow_key][-50:] # 50개 짤 (넘 많이 짜르나)
# tqtqtqtqtqtqtqdddddd
    def rule_based_detection(self, packet_info): 
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        current_time = packet_info['timestamp']

        connections = self.connection_tracker[src_ip]

        # 오래된 connection 제거
        window_start = current_time - self.config['feature_window']
        while connections and connections[0] < window_start: connections.popleft()

        packet_rate = len(connections)

        # ddos
        if packet_rate > 1000: # window: 60 -> 60s 사이 Packet 수
            return {'type': 'ddos', 'severity': 'high', 'rate': packet_rate}
        
        # portscan
        if packet_info['protocol'] == 6: #TCP
            dst_ports = set()
            flow_key = f'{src_ip}->{dst_ip}'

            for pkt in self.flow_cache[flow_key][-100:]: # 최근 패킷 100개 순회
                if pkt['timestamp'] > window_start:
                    dst_ports.add(pkt['dst_port'])
            
            if len(dst_ports) > 20:
                return {'type': 'port_scan', 'severity': 'medium', 'ports': len(dst_ports)}

        if packet_info['packet_size'] > 9000: # 비정상적 크기 패킷
            return {'type': 'large_packet', 'severity': 'low', 'size': packet_info['packet_size']}

        if packet_info['protocol'] not in [1, 6, 17]: # ICMP, TCP, UDP
            return {'type': 'unusual_protocol', 'severity': 'low', 'protocol': packet_info['protocol']}
        
        return None

    def prediction_worker(self): # 머신러닝 예측 워커 스레드 동작 함수
        while self.running:
            try:
                if len(self.packet_buffer) >= self.config['batch_prediction_size']:
                    packets_to_process = [] # 처리할 패킷들
                    for _ in range(min(self.config['batch_prediction_size'], len(self.packet_buffer))):
                        if self.packet_buffer: packets_to_process.append(self.packet_buffer.popleft())

                    # 패킷버퍼에서 가져온 패킷들을 ml 예측 메소드로 넘김
                    if packets_to_process: self.batch_ml_prediction(packets_to_process)

                hub.sleep(1)               
            except Exception as e:
                self.logger.error(f'Error in prediction worker: {e}')
                hub.sleep(5)

    def batch_ml_prediction(self, packets):
        if not self.ml_models: return
        
        start_time = time.time()

        try:
            flow_groups = defaultdict(list)
            for packet in packets:
                flow_key = f'{packet['src_ip']}->{packet['dst_ip']}'
                flow_groups[flow_key].append(packet)
            
            predictions = []

            for flow_key, flow_packets in flow_groups.items():
                features = self.feature_extractor.create_feature_vector(
                    flow_data=flow_packets,
                    window_data=self.get_window_data(flow_packets[0]['src_ip'])
                )

                if not features: continue

                feature_df = pd.DataFrame([features])

                flow_predictions = {}
                for model_name, model_info in self.ml_models.items():
                    try:
                        processed_features = self.preprocess_features(feature_df, model_info)

                        if hasattr(model_info['model'], 'predict_proba'):
                            prob = model_info['model'].predict_proba(processed_features)[0]
                            predictions = prob[1] if len(prob) > 1 else prob[0]
                        else:
                            predictions = model_info['model'].predict(processed_features)[0]
                        
                        flow_predictions[model_name] = float(predictions)
                    except Exception as e:
                        self.logger.debug(f'Prediction error for {model_name}: {e}')
                        continue

                if flow_predictions:
                    avg_prediction = sum(flow_predictions.values()) / len(flow_predictions)

                    predictions.append({
                        'flow_key': flow_key,
                        'src_ip': flow_packets[0]['src_ip'],
                        'prediction': avg_prediction,
                        'model_predictions': flow_predictions,
                        'timestamp': flow_packets[0]['timestamp']
                    })
            
            for pred in predictions: self.process_ml_prediction(pred)

            prediction_time = time.time() - start_time
            self.performance_stats['prediction_time_avg'] = (
                self.performance_stats['prediction_time_avg'] * 0.9 + prediction_time * 0.1
            )

        except Exception as e: self.logger.error(f'Batch prediction error: {e}')

    def preprocess_features(self, feature_df, model_info): 
        processed_df = feature_df.copy()

        expected_features = []
        if hasattr(model_info['model'], 'feature_names_in_'):
            expected_features = model_info['model'].feature_names_in_
        
        if expected_features:
            for col in expected_features:
                if col not in processed_df.dolumns: processed_df[col] = 0
            
            processed_df = processed_df[expected_features]
        
        if model_info['encoders']:
            for col, encoder in model_info['encoders'].items():
                if col in processed_df.columns:
                    try: processed_df[col] = encoder.transform(processed_df[col].astype(str))
                    except Exception as e: processed_df[col] = -1
        
        if model_info['scaler']:
            try: 
                processed_df = pd.DataFrame(
                    model_info['scaler'].transform(processed_df),
                    columns=processed_df.columns
                )
            except Exception as e: self.logger.debug(f'Scaling error: {e}')
        
        return processed_df

    def get_window_data(self, src_ip):
        current_time = time.time()
        window_start = current_time - self.config['feature_window']

        window_packets = []
        for packet in self.packet_buffer:
            if (packet['timestamp'] > window_start and packet['src_ip'] == src_ip):
                window_packets.append(packet)
            
        return window_packets

    def process_ml_prediction(self, prediction): 
        src_ip = prediction['src_ip']
        pred_score = prediction['prediction']

        self.suspicious_ips[src_ip] = max(
            self.suspicious_ips[src_ip],
            pred_score * 100
        )

        if pred_score > self.config['detection_threshold']:
            self.handle_threat(
                {'src_ip': src_ip},
                'ml_detection',
                {
                    'type': 'ml_anomaly',
                    'severity': 'high' if pred_score > 0.9 else 'medium',
                    'score': pred_score,
                    'models': prediction['model_predictions']
                }
            )

    def handle_threat(self, packet_info, detection_method, threat_info):
        src_ip = packet_info['src_ip']

        self.performance_stats['attacks_detected'] += 1

        self.logger.warning(
            f'THREAT DETECTED - Method: {detection_method}, '
            f'Source: {src_ip}, Type: {threat_info['type']}, '
            f'Severity: {threat_info['severity']}'
        )

        if threat_info['severity'] == 'high': self.block_ip(src_ip)
        elif threat_info['severity'] == 'medium':
            self.suspicious_ips[src_ip] += 25
            if self.suspicious_ips[src_ip] > 75: self.block_ip(src_ip, duration=180) # 3m
        elif threat_info['severity'] == 'low': self.suspicious_ips[src_ip] += 10

        self.attack_counters[threat_info['type']] += 1

        self.send_alert(src_ip, detection_method, threat_info)

    def send_alert(self, src_ip, method, threat_info): 
        alert = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': src_ip,
            'detection_method': method,
            'threat_type': threat_info['type'],
            'severity': threat_info['severity'],
            'details': threat_info,
            'action_taken': 'blocked' if src_ip in self.blocked_ips else 'monitored'
        }

        alert_log = os.path.join('logs', 'alerts.json')
        with open(alert_log, 'a') as f: f.write(json.dumps(alert) + '\n')
        
    def forward_packet(self, ev, packet_info):
        msg = ev.smg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        src_mac = packet_info['src_mac']
        dst_mac = packet_info['dst_mac']
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if packet_info['src_ip'] and packet_info['dst_ip']:
            self.ip_to_mac[packet_info['src_ip']] = src_mac
            self.ip_to_mac[packet_info['dst_ip']] = dst_mac
        
        if dst_mac in self.mac_to_port[dpid]: out_port = self.mac_to_port[dpid][dst_mac]
        else: out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=60)
                return
            else: self.add_flow(datapath, 1, match, actions, idle_timeout=60)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )

        datapath.send_msg(out)

    def handle_non_ip_packet(self, ev): 
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        arp_pkt = ptk.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, arp_pkt)
            return

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )

        datapath.send_msg(out)

    def handle_arp(self, datapath, in_port, eth, arp_pkt):
        self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac

        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=eth
        )

        datapath.send_msg(out)

    def cleanup_worker(self): 
        while self.running:
            try:
                current_time = time.time()
                cutoff_time = current_time - self.config['feature_window'] * 2

                for flow_key in list(self.flow_cache.keys()):
                    self.flow_cache[flow_key] = [
                        p for p in self.flow_cache[flow_key]
                        if p['timestamp'] > cutoff_time
                    ]

                    if not self.flow_cache[flow_key]: del self.flow_cache[flow_key]
                
                for ip in list(self.suspicious_ips.keys()):
                    self.suspicious_ips[ip] *= 0.99 # 1% 감소
                    if self.suspicious_ips[ip] < 1.0: del self.suspicious_ips[ip]
                
                for ip in list(self.connection_tracker.keys()):
                    connections = self.connection_tracker[ip]
                    while connections and connections[0] < cutoff_time: connections.popleft()

                    if not connections: del self.connection_tracker[ip]
                
                hub.sleep(30) # 30s 마다 cleanup
            except Exception as e: 
                self.logger.error(f'Error in cleanup worker: {e}')
                hub.sleep(60)

    def stats_worker(self): # 기록 스레드
        while self.running:
            try: 
                self.logger.info(
                    f'Stats - Packets: {self.performance_stats['packets_processed']}, '
                    f'Attacks: {self.performance_stats['attacks_detected']}, '
                    f'Blocked IPs: {len(self.blocked_ips)}, '
                    f'Suspicious IPs: {len(self.suspicious_ips)}, '
                    f'Avg Prediction Time: {self.performance_stats['prediction_time_avg']:.4f}s'
                )

                stats_file = os.path.join('logs', 'performance_stats.json')
                with open(stats_file, 'w') as f:
                    stats_data = {
                        'timestamp': datetime.now().isoformat(),
                        'performance_stats': self.performance_stats,
                        'blocked_ips': list(self.blocked_ips),
                        'suspicious_ips': dict(self.suspicious_ips),
                        'attack_counters': dict(self.attack_counters),
                        'model_count': len(self.ml_models)
                    }
                    json.dump(stats_data, f, indent=2)
                
                hub.sleep(300) # 5분 주기
            except Exception as e: 
                self.logger.error(f'Error in stats worker: {e}')
                hub.sleep(300)

    def get_network_stats(self): 
        return {
            'performance_stats': self.performance_stats,
            'blocked_ips': list(self.blocked_ips),
            'suspicious_ips': dict(self.suspicious_ips),
            'attack_counters': dict(self.attack_counters),
            'active_flows': len(self.flow_cache),
            'connected_switches': len(self.datapaths),
            'ml_models_loaded': len(self.ml_models)
        }

    def reset_stats(self):
        self.performance_stats = {
            'packets_processed': 0,
            'attacks_detected': 0,
            'false_positives': 0,
            'blocked_connections': 0,
            'prediction_time_avg': 0.0,
            'model_accuracy': 0.0
        }
        self.attack_counters.clear()
        self.logger.info('Statistics reset')

    def update_config(self, new_config): 
        self.config.update(new_config)
        self.logger.info(f'Configuration updated: {new_config}')

    def shutdown(self): 
        self.logger.info('Shutting down ML Defense Controller ...')
        self.running = False

        final_stats = self.get_network_stats()
        with open(os.path.join('logs', 'final_stats.json'), 'w') as f:
            json.dump(final_stats, f, indent=2)
        
        self.logger.info('Shutdown complete')