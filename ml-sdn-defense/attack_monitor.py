#!/usr/bin/env python3

import os
import json
import logging
from datetime import datetime
from collections import defaultdict, deque
import pandas as pd

class AttackMonitor:
    def __init__(self, log_dir='logs/attacks'):
        """공격 모니터링 및 로깅"""
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        
        self.attack_stats = {
            'total_attacks': 0,
            'attacks_by_type': defaultdict(int),
            'attacks_by_ip': defaultdict(int),
            'blocked_ips': set()
        }
        
        self.recent_attacks = deque(maxlen=1000)
        
        self.setup_logging()

    def setup_logging(self):
        """로깅 설정"""
        log_file = os.path.join(self.log_dir, f'attacks_{datetime.now().strftime("%Y%m%d")}.log')
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)

    def log_attack(self, packet_info, attack_type, confidence):
        """공격 로깅"""
        attack_record = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': packet_info.get('src_ip', 'unknown'),
            'dst_ip': packet_info.get('dst_ip', 'unknown'),
            'src_port': packet_info.get('src_port', 0),
            'dst_port': packet_info.get('dst_port', 0),
            'protocol': packet_info.get('protocol', 0),
            'attack_type': attack_type,
            'confidence': float(confidence)
        }
        
        # 통계 업데이트
        self.attack_stats['total_attacks'] += 1
        self.attack_stats['attacks_by_type'][attack_type] += 1
        self.attack_stats['attacks_by_ip'][packet_info.get('src_ip', 'unknown')] += 1
        
        # 최근 공격 이력에 추가
        self.recent_attacks.append(attack_record)
        
        # 로그 파일에 기록
        self.logger.warning(f"Attack detected: {json.dumps(attack_record)}")
        
        # JSON 파일로도 저장 (일별)
        self._save_attack_json(attack_record)

    def update_blocked_count(self, src_ip, attack_type):
        """차단된 IP 업데이트"""
        self.attack_stats['blocked_ips'].add(src_ip)
        self.logger.info(f"IP {src_ip} blocked due to {attack_type}")

    def _save_attack_json(self, attack_record):
        """공격 기록을 JSON 파일로 저장"""
        date_str = datetime.now().strftime('%Y%m%d')
        json_file = os.path.join(self.log_dir, f'attacks_{date_str}.json')
        
        try:
            # 기존 데이터 읽기
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    data = json.load(f)
            else:
                data = []
            
            # 새 공격 추가
            data.append(attack_record)
            
            # 저장
            with open(json_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save attack JSON: {e}")

    def get_statistics(self):
        """통계 정보 반환"""
        return {
            'total_attacks': self.attack_stats['total_attacks'],
            'attacks_by_type': dict(self.attack_stats['attacks_by_type']),
            'unique_attackers': len(self.attack_stats['attacks_by_ip']),
            'blocked_ips_count': len(self.attack_stats['blocked_ips']),
            'recent_attacks_count': len(self.recent_attacks)
        }

    def get_recent_attacks(self, n=10):
        """최근 공격 이력 반환"""
        return list(self.recent_attacks)[-n:]

    def get_top_attackers(self, n=10):
        """상위 공격자 IP 목록"""
        sorted_ips = sorted(
            self.attack_stats['attacks_by_ip'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_ips[:n]

    def generate_report(self, output_file=None):
        """공격 리포트 생성"""
        if output_file is None:
            output_file = os.path.join(
                self.log_dir,
                f'attack_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
            )
        
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("ATTACK DETECTION REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # 전체 통계
            f.write("OVERALL STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Attacks Detected: {self.attack_stats['total_attacks']}\n")
            f.write(f"Unique Attackers: {len(self.attack_stats['attacks_by_ip'])}\n")
            f.write(f"Blocked IPs: {len(self.attack_stats['blocked_ips'])}\n\n")
            
            # 공격 유형별 통계
            f.write("ATTACKS BY TYPE\n")
            f.write("-" * 80 + "\n")
            for attack_type, count in sorted(
                self.attack_stats['attacks_by_type'].items(),
                key=lambda x: x[1],
                reverse=True
            ):
                f.write(f"{attack_type}: {count}\n")
            f.write("\n")
            
            # 상위 공격자
            f.write("TOP 10 ATTACKERS\n")
            f.write("-" * 80 + "\n")
            for ip, count in self.get_top_attackers(10):
                f.write(f"{ip}: {count} attacks\n")
            f.write("\n")
            
            # 최근 공격
            f.write("RECENT ATTACKS (Last 20)\n")
            f.write("-" * 80 + "\n")
            for attack in self.get_recent_attacks(20):
                f.write(f"{attack['timestamp']} - {attack['src_ip']} -> {attack['dst_ip']}: "
                       f"{attack['attack_type']} (confidence: {attack['confidence']:.2f})\n")
        
        self.logger.info(f"Report generated: {output_file}")
        return output_file

    def export_to_csv(self, output_file=None):
        """공격 이력을 CSV로 내보내기"""
        if output_file is None:
            output_file = os.path.join(
                self.log_dir,
                f'attacks_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            )
        
        if self.recent_attacks:
            df = pd.DataFrame(list(self.recent_attacks))
            df.to_csv(output_file, index=False)
            self.logger.info(f"Attacks exported to CSV: {output_file}")
            return output_file
        else:
            self.logger.warning("No attacks to export")
            return None