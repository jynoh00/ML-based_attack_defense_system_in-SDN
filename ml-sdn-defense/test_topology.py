#!/usr/bin/env python3

"""
Mininet 테스트 토폴로지 (강화된 공격 버전)
더 명확한 공격 패턴으로 ML 탐지 테스트
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time

def create_topology():
    """테스트 네트워크 토폴로지 생성"""
   
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
   
    info('*** Adding controller\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )
   
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
   
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')
   
    info('*** Creating links\n')
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)
    net.addLink(h4, s1, bw=10)
    net.addLink(s1, s2, bw=100)
    net.addLink(s2, h5, bw=10)
    net.addLink(s2, h6, bw=10)
   
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
   
    info('*** Network started successfully!\n')
    info('*** Hosts:\n')
    for host in net.hosts:
        info(f'  {host.name}: {host.IP()}\n')
   
    return net

def run_strong_attacks(net):
    """강화된 공격 시나리오 - ML이 탐지할 수 있도록"""
    h1, h2, h3, h4, h5 = net.get('h1', 'h2', 'h3', 'h4', 'h5')
   
    info('\n' + '='*70 + '\n')
    info('STRONG ATTACK SCENARIOS (ML Detection)\n')
    info('='*70 + '\n')
    info('Target: h5 (10.0.0.5)\n')
    info('Attackers: h1 (Port Scan), h2 (SYN Flood), h3 (DoS)\n')
    info('='*70 + '\n\n')
   
    # 정상 트래픽 먼저 생성 (baseline)
    info('0. Establishing baseline normal traffic...\n')
    h4.cmd('ping -c 5 10.0.0.5 > /dev/null 2>&1 &')
    time.sleep(2)
   
    # 1. 강화된 Port Scan (더 많은 포트, 더 빠르게)
    info('1. INTENSE Port Scan Attack (h1 -> h5)\n')
    info('   Scanning 200 ports rapidly...\n')
   
    # Python으로 빠른 포트 스캔
    port_scan_script = '''
import socket
import time
target = "10.0.0.5"
for port in range(1, 201):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((target, port))
        s.close()
    except:
        pass
    time.sleep(0.01)  # 10ms 간격
print("Port scan completed")
'''
   
    with open('/tmp/port_scan.py', 'w') as f:
        f.write(port_scan_script)
   
    h1.cmd('python3 /tmp/port_scan.py > /tmp/h1_portscan.log 2>&1 &')
    info('   ✓ Port scan started (200 ports)\n')
    time.sleep(5)  # 5초 대기
    info('   Waiting for ML detection...\n\n')
   
    # 2. 강화된 SYN Flood (더 많은 패킷)
    info('2. INTENSE SYN Flood Attack (h2 -> h5)\n')
    info('   Sending 500 SYN packets...\n')
   
    syn_flood_script = '''
import socket
import random
target = "10.0.0.5"
port = 80
for i in range(500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        # SYN 패킷만 보내고 바로 close (3-way handshake 완료 안함)
        s.connect_ex((target, port))
        s.close()
    except:
        pass
print("SYN flood completed")
'''
   
    with open('/tmp/syn_flood.py', 'w') as f:
        f.write(syn_flood_script)
   
    h2.cmd('python3 /tmp/syn_flood.py > /tmp/h2_synflood.log 2>&1 &')
    info('   ✓ SYN flood started (500 packets)\n')
    time.sleep(5)
    info('   Waiting for ML detection...\n\n')
   
    # 3. 강화된 Ping Flood (ICMP)
    info('3. INTENSE Ping Flood Attack (h3 -> h5)\n')
    info('   Sending 500 ping packets...\n')
    h3.cmd('ping -f -c 500 10.0.0.5 > /tmp/h3_pingflood.log 2>&1 &')
    info('   ✓ Ping flood started\n')
    time.sleep(5)
    info('   Waiting for ML detection...\n\n')
   
    # 4. HTTP Flood (추가 공격)
    info('4. HTTP Flood Attack (h1 -> h5)\n')
    info('   Sending 100 HTTP requests...\n')
   
    http_flood_script = '''
import socket
target = "10.0.0.5"
port = 80
request = b"GET / HTTP/1.1\\r\\nHost: 10.0.0.5\\r\\n\\r\\n"
for i in range(100):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target, port))
        s.send(request)
        s.close()
    except:
        pass
print("HTTP flood completed")
'''
   
    with open('/tmp/http_flood.py', 'w') as f:
        f.write(http_flood_script)
   
    h1.cmd('python3 /tmp/http_flood.py > /tmp/h1_httpflood.log 2>&1 &')
    info('   ✓ HTTP flood started\n')
    time.sleep(5)
    info('   Waiting for ML detection...\n\n')
   
    info('='*70 + '\n')
    info('All attacks launched! Check controller logs for detection.\n')
    info('='*70 + '\n\n')
   
    # 공격 완료 대기
    info('Waiting 10 seconds for attacks to complete...\n')
    time.sleep(10)
   
    # 결과 확인
    info('\n' + '='*70 + '\n')
    info('VERIFICATION\n')
    info('='*70 + '\n\n')
   
    # 정상 트래픽 테스트
    info('Testing normal traffic from h4 (should work):\n')
    result = h4.cmd('ping -c 3 -W 2 10.0.0.5')
    if 'bytes from' in result:
        info('✓ h4 can reach h5 (normal traffic allowed)\n\n')
    else:
        info('✗ h4 cannot reach h5 (might be false positive)\n\n')
   
    # 공격자 차단 확인
    info('Testing if attackers are blocked:\n')
    for attacker in [h1, h2, h3]:
        result = attacker.cmd('ping -c 2 -W 2 10.0.0.5')
        if 'bytes from' in result:
            info(f'✗ {attacker.name} NOT blocked (IP: {attacker.IP()})\n')
        else:
            info(f'✓ {attacker.name} BLOCKED (IP: {attacker.IP()})\n')
   
    # 공격 로그 확인
    info('\nAttack execution logs:\n')
    for log_file in ['/tmp/h1_portscan.log', '/tmp/h2_synflood.log', '/tmp/h3_pingflood.log']:
        result = h1.cmd(f'tail -2 {log_file} 2>/dev/null || echo "No log"')
        info(f'  {log_file}: {result}')

def stop_attacks(net):
    """실행 중인 공격 중단"""
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
   
    info('\n*** Stopping attacks...\n')
    h1.cmd('killall python3 nmap nc 2>/dev/null')
    h2.cmd('killall python3 hping3 2>/dev/null')
    h3.cmd('killall ping 2>/dev/null')
    info('*** Attacks stopped\n')

def interactive_attack_menu(net):
    """대화형 공격 메뉴"""
    h1, h2, h3, h4, h5 = net.get('h1', 'h2', 'h3', 'h4', 'h5')
   
    while True:
        info('\n' + '='*70 + '\n')
        info('ATTACK MENU\n')
        info('='*70 + '\n')
        info('1. Port Scan (h1 -> h5)\n')
        info('2. SYN Flood (h2 -> h5)\n')
        info('3. Ping Flood (h3 -> h5)\n')
        info('4. Run ALL attacks\n')
        info('5. Test normal traffic (h4 -> h5)\n')
        info('6. Check block status\n')
        info('7. View controller logs\n')
        info('0. Exit to CLI\n')
        info('='*70 + '\n')
       
        choice = input('Select option: ').strip()
       
        if choice == '1':
            info('\nLaunching Port Scan...\n')
            h1.cmd('python3 /tmp/port_scan.py > /tmp/attack.log 2>&1 &')
            time.sleep(5)
            info('Port scan completed. Check controller logs.\n')
           
        elif choice == '2':
            info('\nLaunching SYN Flood...\n')
            h2.cmd('python3 /tmp/syn_flood.py > /tmp/attack.log 2>&1 &')
            time.sleep(5)
            info('SYN flood completed. Check controller logs.\n')
           
        elif choice == '3':
            info('\nLaunching Ping Flood...\n')
            h3.cmd('ping -f -c 500 10.0.0.5 > /tmp/attack.log 2>&1 &')
            time.sleep(5)
            info('Ping flood completed. Check controller logs.\n')
           
        elif choice == '4':
            run_strong_attacks(net)
           
        elif choice == '5':
            info('\nTesting normal traffic...\n')
            result = h4.cmd('ping -c 3 10.0.0.5')
            info(result)
           
        elif choice == '6':
            info('\nChecking block status...\n')
            for attacker in [h1, h2, h3]:
                result = attacker.cmd('ping -c 1 -W 1 10.0.0.5')
                status = 'BLOCKED' if 'bytes from' not in result else 'NOT BLOCKED'
                info(f'{attacker.name} ({attacker.IP()}): {status}\n')
               
        elif choice == '7':
            info('\nRecent controller logs (last 20 lines):\n')
            import subprocess
            try:
                logs = subprocess.run(
                    ['tail', '-20', 'logs/attacks/attacks_*.log'],
                    capture_output=True, text=True, shell=True
                )
                info(logs.stdout if logs.stdout else 'No logs found\n')
            except:
                info('Could not read logs\n')
               
        elif choice == '0':
            break
        else:
            info('Invalid option\n')

def main():
    setLogLevel('info')
   
    net = create_topology()
   
    try:
        info('\n*** Testing connectivity\n')
        net.pingAll()
       
        # 공격 스크립트 준비
        info('\n*** Preparing attack scripts...\n')
       
        info('\n*** Attack Mode Selection:\n')
        info('1. Run automated attack scenarios\n')
        info('2. Interactive attack menu\n')
        info('3. Skip attacks (CLI only)\n')
       
        mode = input('Select mode (1/2/3): ').strip()
       
        if mode == '1':
            run_strong_attacks(net)
            info('\n*** Press Enter to stop attacks and enter CLI...')
            input()
            stop_attacks(net)
           
        elif mode == '2':
            # 공격 스크립트 미리 생성
            h1 = net.get('h1')
           
            port_scan_script = '''
import socket
import time
target = "10.0.0.5"
for port in range(1, 201):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((target, port))
        s.close()
    except:
        pass
    time.sleep(0.01)
'''
            h1.cmd(f'echo \'{port_scan_script}\' > /tmp/port_scan.py')
           
            syn_flood_script = '''
import socket
target = "10.0.0.5"
for i in range(500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect_ex((target, 80))
        s.close()
    except:
        pass
'''
            h1.cmd(f'echo \'{syn_flood_script}\' > /tmp/syn_flood.py')
           
            interactive_attack_menu(net)
       
        info('\n*** Starting CLI\n')
        info('*** Available commands:\n')
        info('  pingall       - Test connectivity\n')
        info('  h1 ping h5    - Ping from h1 to h5\n')
        info('  xterm h1      - Open terminal on h1\n')
        info('  exit          - Stop network\n\n')
       
        CLI(net)
       
    finally:
        stop_attacks(net)
        info('\n*** Stopping network\n')
        net.stop()

if __name__ == '__main__':
    main()