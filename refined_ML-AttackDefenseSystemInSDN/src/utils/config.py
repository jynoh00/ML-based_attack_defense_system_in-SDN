#!/usr/bin/env python3

import os
import json
import yaml

class Config:
    """설정 관리 클래스"""
    
    def __init__(self, config_file='config/config.yaml'):
        self.config_file = config_file
        self.config = self.load_config()

    def load_config(self):
        """설정 파일 로드"""
        if not os.path.exists(self.config_file):
            return self.get_default_config()
        
        try:
            with open(self.config_file, 'r') as f:
                if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                    return yaml.safe_load(f)
                elif self.config_file.endswith('.json'):
                    return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.get_default_config()

    def get_default_config(self):
        """기본 설정"""
        return {
            'sdn': {
                'controller_port': 6633,
                'ofp_version': '1.3',
                'idle_timeout': 30,
                'hard_timeout': 300
            },
            'ml': {
                'model_path': 'data/models/best_model.pkl',
                'scaler_path': 'data/processed/cicids2017/scaler.pkl',
                'encoders_path': 'data/processed/cicids2017/encoders.pkl',
                'attack_threshold': 0.95,
                'window_size': 60
            },
            'defense': {
                'auto_block': True,
                'block_duration': 300,
                'max_blocked_ips': 1000
            },
            'monitoring': {
                'log_dir': 'logs/attacks',
                'enable_csv_export': True,
                'report_interval': 3600
            },
            'performance': {
                'flow_cleanup_interval': 300,
                'max_flows_cache': 10000,
                'packet_buffer_size': 10000
            }
        }

    def save_config(self, config_file=None):
        """설정 저장"""
        if config_file is None:
            config_file = self.config_file
        
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        with open(config_file, 'w') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                yaml.dump(self.config, f, default_flow_style=False)
            elif config_file.endswith('.json'):
                json.dump(self.config, f, indent=2)

    def get(self, *keys, default=None):
        """중첩된 키로 설정 값 가져오기"""
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, *keys, value):
        """중첩된 키로 설정 값 설정"""
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value