#!/usr/bin/env python3

# 특징 추출 (n차원 입력값 -> m차원 특징벡터로 변환)

import pandas as pd
import numpy as np
from collections import defaultdict, Counter

from sklearn.feature_selection import SelectKBest, chi2, f_classif, mutual_info_classif
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier

import time
from datetime import datetime, timedelta
import pickle
import os
import argparse
import json
import joblib

class FeatureExtractor:
    def __init__(self):
        self.flow_cache = defaultdict(dict)
        self.connection_states = defaultdict(str)
        self.time_window = 60

        self.basic_features = [
            'duration', 'protocol_type', 'service', 'flag',
            'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent'
        ]

        self.content_features = [
            'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login'
        ]

        self.time_features = [
            'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate'
        ]

        self.host_features = [
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate'
        ]

        self.advanced_features = [
            'packet_rate', 'byte_rate', 'flow_duration_mean', 'flow_duration_std',
            'packet_size_mean', 'packet_size_std', 'inter_arrival_time_mean',
            'inter_arrival_time_std', 'port_scan_score', 'ddos_score',
            'tcp_flag_distribution', 'protocol_distribution'
        ]

    def extract_packet_features(self, packet_data): # 패킷 정보 추출 메소드
        features = {}

        # packet 기본 정보
        features['src_ip'] = packet_data.get('src_ip', '0.0.0.0')
        features['dst_ip'] = packet_data.get('dst_ip', '0.0.0.0')
        features['src_port'] = packet_data.get('src_port', 0)
        features['dst_port'] = packet_data.get('dst_port', 0)
        features['protocol'] = packet_data.get('protocol', 0)
        features['packet_size'] = packet_data.get('packet_size', 0)
        features['timestamp'] = packet_data.get('timestamp', time.time())

        # TCP 프로토콜 flag
        features['tcp_flags'] = packet_data.get('tcp_flags', 0)
        features['syn_flag'] = 1 if features['tcp_flags'] & 0x02 else 0
        features['ack_flag'] = 1 if features['tcp_flags'] & 0x10 else 0
        features['fin_flag'] = 1 if features['tcp_flags'] & 0x01 else 0
        features['rst_flag'] = 1 if features['tcp_flags'] & 0x04 else 0
        features['psh_flag'] = 1 if features['tcp_flags'] & 0x08 else 0
        features['urg_flag'] = 1 if features['tcp_flags'] & 0x20 else 0

        return features
    
    def extract_flow_features(self, flow_packets): # 플로우 정보 추출 메소드
        if not flow_packets: return {}

        features = {}
        
        # flow 식별자
        first_packet = flow_packets[0]
        features['src_ip'] = first_packet['src_ip']
        features['dst_ip'] = first_packet['dst_ip']
        features['src_port'] = first_packet['src_port']
        features['dst_port'] = first_packet['dst_port']
        features['protocol'] = first_packet['protocol']

        # flow 통계 정보
        features['flow_duration'] = flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp']
        features['packet_count'] = len(flow_packets)
        features['total_bytes'] = sum(p['packet_size'] for p in flow_packets)

        # flow 내 패킷 크기 통계 정보
        packet_sizes = [p['packet_size'] for p in flow_packets]
        features['packet_size_mean'] = np.mean(packet_sizes)
        features['packet_size_std'] = np.std(packet_sizes) # np.std??
        features['packet_size_min'] = np.min(packet_sizes)
        features['packet_size_max'] = np.max(packet_sizes)

        if len(flow_packets) > 1:
            inter_arrival_times = [ # 패킷간 사이 간격 시간
                flow_packets[i]['timestamp'] - flow_packets[i-1]['timestamp']
                for i in range(1, len(flow_packets)) 
            ]

            features['inter_arrival_time_mean'] = np.mean(inter_arrival_times)
            features['inter_arrival_time_std'] = np.std(inter_arrival_times)
        else:
            features['inter_arrival_time_mean'] = 0
            features['inter_arrival_time_std'] = 0

        if features['flow_duration'] > 0:
            features['packet_rate'] = features['packet_count'] / features['flow_duration']
            features['byte_rate'] = features['total_bytes'] / features['flow_duration']
        else:
            features['packet_rate'] = 0
            features['byte_rate'] = 0

        # TCP 프로토콜 flag 개수합 통계 정보
        tcp_flags = [p.get('tcp_flags', 0) for p in flow_packets]
        features['syn_count'] = sum(1 for f in tcp_flags if f & 0x02)
        features['ack_count'] = sum(1 for f in tcp_flags if f & 0x10)
        features['fin_count'] = sum(1 for f in tcp_flags if f & 0x01)
        features['rst_count'] = sum(1 for f in tcp_flags if f & 0x04)
        features['psh_count'] = sum(1 for f in tcp_flags if f & 0x08)
        features['urg_count'] = sum(1 for f in tcp_flags if f & 0x20)

        return features
    
    def extract_window_features(self, flows, window_size=60): # 윈도우 내 플로우 정보 추출
        current_time = time.time()
        window_start = current_time - window_size

        window_flows = [f for f in flows if f.get('timestamp', 0) >= window_start] # 윈도우 크기 만큼의 flows 추출?

        features = {}

        if not window_flows: return self._get_empty_window_features()

        unique_connections = set()
        src_ips = set(); dst_ips = set(); dst_ports = set()
        protocols = []

        for flow in window_flows:
            conn = (flow['src_ip'], flow['dst_ip'], flow['src_port'], flow['dst_port'])
            unique_connections.add(conn)
            src_ips.add(flow['src_ip'])
            dst_ips.add(flow['dst_ip'])
            dst_ports.add(flow['dst_port'])
            protocols.append(flow['protocol'])
        
        features['unique_connections'] = len(unique_connections)
        features['unique_src_ips'] = len(src_ips)
        features['unique_dst_ips'] = len(dst_ips)
        features['unique_dst_ports'] = len(dst_ports)

        protocol_counts = Counter(protocols)
        total_flows = len(window_flows)
        features['tcp_ratio'] = protocol_counts.get(6, 0) / total_flows
        features['udp_ratio'] = protocol_counts.get(17, 0) / total_flows
        features['icmp_ratio'] = protocol_counts.get(1, 0) / total_flows

        features['port_scan_score'] = self._calculate_port_scan_score(window_flows)
        features['ddos_score'] = self._calculate_ddos_score(window_flows)

        total_packets = sum(f.get('packet_count', 0) for f in window_flows)
        total_bytes = sum(f.get('total_bytes', 0) for f in window_flows)

        features['total_packets_window'] = total_packets
        features['total_bytes_window'] = total_bytes
        features['avg_packets_per_flow'] = total_packets / len(window_flows)
        features['avg_bytes_per_flow'] = total_bytes / len(window_flows)

        return features
        
    def _get_empty_window_features(self): # data가 없는 경우 return 0
        return {
            'unique_connections': 0, 'unique_src_ips': 0, 'unique_dst_ips': 0,
            'unique_dst_ports': 0, 'tcp_ratio': 0, 'udp_ratio': 0, 'icmp_ratio': 0,
            'port_scan_score': 0, 'ddos_score': 0, 'total_packets_window': 0,
            'total_bytes_window': 0, 'avg_packets_per_flow': 0, 'avg_bytes_per_flow': 0
        }

    def _calculate_port_scan_score(self, flows): # 포트 스캔 공격 탐지용 점수 계산
        src_ip_ports = defaultdict(set)

        # key: src_ip, values: set로 dst_port들(중복 x)
        for flow in flows: src_ip_ports[flow['src_ip']].add(flow['dst_port'])

        max_ports = 0
        total_unique_ports = 0

        for _, ports in src_ip_ports.items(): # _ = src_ip
            port_count = len(ports)
            max_ports = max(max_ports, port_count)
            total_unique_ports += port_count
        
        if len(src_ip_ports) == 0: return 0

        avg_ports_per_src = total_unique_ports / len(src_ip_ports)
        port_scan_score = min(1.0, (max_ports * avg_ports_per_src) / 100)

        return port_scan_score        

    def _calculate_ddos_score(self, flows):
        if not flows: return 0

        dst_ip_counts = Counter(flow['dst_ip'] for flow in flows)

        total_flows = len(flows)
        max_dst_count = max(dst_ip_counts.values() if dst_ip_counts else 0) # 가장 많은 트래픽을 받은 dst_ip의 플로우 수

        concentration_ratio = max_dst_count / total_flows # 전체 트래픽에서 dst_ip에 집중된 비율 (모든 dst_ip 중 가장 많은 트래픽을 받은)

        time_span = max(f.get('timestamp', 0) for f in flows) - min(f.get('timestamp', 0) for f in flows) # 전체 플로우에서 전체 시간 간격
        flow_rate = total_flows / max(time_span, 1) # 전체 플로우 수 / 전체 시간 간격 => 초당 플로우 수
        
        ddos_score = min(1.0, concentration_ratio * (flow_rate / 100))
        # 전체 트래픽에서 dst_ip에 집중된 비율 * (초당 플로우 수 / 100)
        # ddos_score = 집중도 x 유입률 * 0.01

        return ddos_score

    def extract_statistical_features(self, flows): # 플로우들에서 통계 feature 추출
        if not flows: return {}

        features = {}

        # numerical values
        durations = [f.get('flow_duration', 0) for f in flows]
        packet_counts = [f.get('packet_count', 0) for f in flows]
        byte_counts = [f.get('total_bytes', 0) for f in flows]
        packet_rates = [f.get('packdt_rate', 0) for f in flows]
        byte_rates = [f.get('byte_rate', 0) for f in flows]

        for name, values in [
            ('duration', durations), ('packet_count', packet_counts),
            ('byte_count', byte_counts), ('packet_rate', packet_rates),
            ('byte_rate', byte_rates)
        ]:
            if values:
                features[f'{name}_mean'] = np.mean(values)
                features[f'{name}_std'] = np.std(values)
                features[f'{name}_min'] = np.min(values)
                features[f'{name}_max'] = np.max(values)
                features[f'{name}_median'] = np.median(values)
                features[f'{name}_q25'] = np.percentile(values, 25)
                features[f'{name}_q75'] = np.percentile(values, 75)
            else:
                for suffix in ['_mean', '_std', '_min', '_max', '_median', '_q25', '_q75']: features[f'{name}{suffix}'] = 0

        return features
    
    def create_feature_vector(self, packet_data=None, flow_data=None, window_data=None):    
        features = {}

        if packet_data:
            packet_features = self.extract_packet_features(packet_data)
            features.update({f'pkt_{k}' : v for k, v in packet_features.items()})
        
        if flow_data:
            flow_features = self.extract_flow_features(flow_data)
            features.update({f'flow_{k}' : v for k, v in flow_features.items()})
        
        if window_data:
            window_features = self.extract_window_features(window_data)
            features.update({f'win_{k}' : v for k, v in window_features.items()})
        
            stats_features = self.extract_statistical_features(window_data)
            features.update({f'stat_{k}' : v for k, v in stats_features.items()})

        return features
        
    def select_best_features(self, X, y, method='mutual_info', k=50):
        print(f'Selected top {k} features using {method} ...')

        if method == 'chi2':
            X_positive = X - X.min() + 1e-6
            selector = SelectKBest(score_func=chi2, k=k)
            X_selected = selector.fit_transform(X_positive, y)
        
        elif method == 'f_classif':
            selector = SelectKBest(score_func=f_classif, k=k)
            X_selected = selector.fit_transform(X, y)
        
        elif method == 'mutual_info':
            selector = SelectKBest(score_func=mutual_info_classif, k=k)
            X_selected = selector.fit_transform(X, y)
        
        elif method == 'random_forest':
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            rf.fit(X, y)
        
            feature_importance = pd.Series(rf.feature_importances_, index=X.columns)
            top_features = feature_importance.nlargest(k).index.tolist()

            X_selected = X[top_features]
            selector = top_features
        
        else: raise ValueError('Method must be one of: chi2, f_classif, mutual_info, random_forest')

        if method != 'random_forest': selected_features = X.columns[selector.get_support()].tolist()
        else: selected_features = selector

        print(f'Selected features: {selected_features[:10]} ...')

        return X_selected, selected_features, selector

    def apply_pca(self, X_train, X_test=None, n_components=0.95):
        # 차원 감소를 위한 PCA 적용
        print(f'Applying PCA with {n_components} components ...')

        pca = PCA(n_components=n_components)
        X_train_pca = pca.fit_transform(X_train)

        print(f'Reduced dimensions from {X_train.shape[1]} to {X_train_pca.shape[1]}')
        print(f'Explained variance ratio: {pca.explained_variance_ratio_.sum():.4f}')

        if X_test is not None:
            X_test_pca = pca.transform(X_test)
            return X_train_pca, X_test_pca, pca
    
        return X_train_pca, pca

    def create_advanced_features(self, df):
        print('Creating advanced engineered features ...')

        advanced_df = df.copy()

        if 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
            total_bytes = df['src_bytes'] + df['dst_bytes']
            advanced_df['src_dst_bytes_ratio'] = np.where(total_bytes > 0, df['src_bytes'] / total_bytes, 0)
        
        if 'duration' in df.columns:
            advanced_df['duration_log'] = np.log1p(df['duration'])
            advanced_df['is_short_connection'] = (df['duration'] < 1).astype(int)
            advanced_df['is_long_connection'] = (df['duration'] > 3600).astype(int)
        
        if 'count' in df.columns and 'srv_count' in df.columns:
            advanced_df['count_srv_ratio'] = np.where(df['srv_count'] > 0, df['count'] / df['srv_count'], 0)
        
        error_cols = [col for col in df.columns if 'error_rate' in col]
        if error_cols:
            advanced_df['total_error_rate'] = df[error_cols].sum(axis=1)
            advanced_df['avg_error_rate'] = df[error_cols].mean(axis=1)

        host_count_cols = [col for col in df.columns if 'dst_host' in col and 'count' in col]
        if host_count_cols:
            advanced_df['total_host_count'] = df[host_count_cols].sum(axis=1)
        
        if 'dst_port' in df.columns:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
            advanced_df['is_common_port'] = df['dst_port'].isin(common_ports).astype(int)

            advanced_df['is_well_known_port'] = (df['dst_port'] <= 1023).astype(int) # well known 0-1023
            advanced_df['is_ephemeral_port'] = (df['dst_port' >= 32768]).astype(int) # ephemeral ports

        print(f'Added {len(advanced_df.columns) - len(df.columns)} advanced features')

        return advanced_df

    def save_feature_extractor(self, filepath): 
        config = {
            'basic_features': self.basic_features,
            'content_features': self.content_features,
            'time_features': self.time_features,
            'host_features': self.host_features,
            'advanced_features': self.advanced_features,
            'time_window': self.time_windows
        }

        with open(filepath, 'wb') as f: pickle.dump(config, f)
        
        print(f'Feature extractor saved to {filepath}')

    def load_feature_extractor(self, filepath):
        with open(filepath, 'rb') as f: config = pickle.load(f)

        self.basic_features = config['basic_features']
        self.content_features = config['content_features']
        self.time_features = config['time_features']
        self.host_features = config['host_features']
        self.advanced_features = config['advanced_features']
        self.time_window = config['time_window']

        print(f'Feature extractor loaded from {filepath}')


def main():
    parser = argparse.ArgumentParser(description='Feature Extraction')
    parser.add_argument('--input', required=True, help='Input CSV file')
    parser.add_argument('--output', required=True, help='Output directory')
    parser.add_argument('--method', choices=['chi2', 'f_classif', 'mutual_info', 'random_forest'], default='mutual_info', help='Feature selection method')
    parser.add_argument('--k', type=int, default=50, help='Number of features to select')
    parser.add_argument('--pca', action='store_true', help='Apply PCA')
    parser.add_argument('--pca-components', type=float, default=0.95, help='PCA components (ratio or number)')

    args = parser.parse_args()

    print(f'Loading data from {args.input} ...')
    df = pd.read_csv(args.input)

    if 'Label' in df.columns:
        X = df.drop('Label', axis=1)
        y = df['Label']
        label_col = 'Label'
    elif 'class' in df.columns:
        X = df.drop('class', axis=1)
        y = df['class']
        label_col = 'class'
    else: raise ValueError('No label column found ("Label" or "class")')

    extractor = FeatureExtractor()
    
    X_advanced = extractor.create_advanced_features(X)
    X_selected, selected_features, selector = extractor.select_best_features(X_advanced, y, method=args.method, k=args.k)

    if args.pca:
        X_final, pca = extractor.apply_pca(X_selected, n_components=args.pca_components)
        pca_columns = [f'PC{i+1}' for i in range(X_final.shape[1])]
        X_final = pd.DataFrame(X_final, columns=pca_columns)
    else:
        if hasattr(X_selected, 'columns'): X_final = X_selected
        else: X_final = pd.DataFrame(X_selected, columns=selected_features)
        pca = None
    
    os.makedirs(args.output, exist_ok=True)

    X_final.to_csv(os.path.join(args.output, 'X_processed.csv'), index=False)
    y.to_csv(os.path.join(args.output, 'y.csv'), index=False)

    feature_info = {
        'original_features': list(X.columns),
        'advanced_features': list(X_advanced.columns),
        'selected_features': selected_features,
        'selection_method': args.method,
        'k': args.k,
        'pca_applied': args.pca
    }

    with open(os.path.join(args.output, 'feature_info.json'), 'w') as f: json.dump(feature_info, f, indent=2)
    joblib.dump(selector, os.path.join(args.output, 'feature_selector.pkl'))
    if pca: joblib.dump(pca, os.path.join(args.output, 'pca.pkl'))

    extractor.save_feature_extractor(os.path.join(args.output, 'feature_extractor.pkl'))

    print(f'\nFeature extraction completed.')
    print(f'Original features: {X.shape[1]}')
    print(f'Advanced features: {X_advanced.shape[1]}')
    print(f'Selected features: {X_final.shape[1]}')
    print(f'Output saved to: {args.output}')

if __name__ == '__main__': main()