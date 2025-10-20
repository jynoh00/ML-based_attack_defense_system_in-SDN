#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host, OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
from mininet.term import makeTerm
from mininet.util import dumpNodeConnections

import time
import os
import threading
import subprocess
import argparse

class NetworkTopology:
    def __init__(self, controller_ip='127.0.0.1', controller_port=6653):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.net = None
        self.hosts = {}
        self.switches = {}
        self.links = []

        self.config = {
            'ip_base': '10.0.0.0/8',
            'auto_set_macs': True,
            'cleanup': True,
            'link_defaults': {
                'bw': 10, # 10Mbps
                'delay': '5ms',
                'loss': 0,
                'max_queue_size': 1000
            }
        }

    def create_enterprise_topology(self):
        info('*** Creating Enterprise Network Topology\n')
        self.net = Mininet(
            topo=None,
            build=False,
            ipBase=self.config['ip_base'],
            link=TCLink,
            autosetMacs=self.config['auto_set_macs'],
            cleanup=self.config['cleanup']
        )

        info('*** Adding controller\n')
        controller = self.net.addController(
            'c0',
            controller=RemoteController,
            ip=self.controller_ip,
            port=self.controller_port,
            protocols='OpenFlow13'
        )

        info('*** Adding core switches\n')
        core1 = self.net.addSwitch('core1', protocols='OpenFlow13', failMode='secure')
        core2 = self.net.addSwitch('core2', protocols='OpenFlow13', failMode='secure')

        agg1 = self.net.addSwitch('agg1', protocols='OpenFlow13', failMode='secure')
        agg2 = self.net.addSwitch('agg2', protocols='OpenFlow13', failMode='secure')
        agg3 = self.net.addSwitch('agg3', protocols='OpenFlow13', failMode='secure')

        access1 = self.net.addSwitch('access1', protocols='OpenFlow13', failMode='secure')
        access2 = self.net.addSwitch('access2', protocols='OpenFlow13', failMode='secure')
        access3 = self.net.addSwitch('access3', protocols='OpenFlow13', failMode='secure')
        access4 = self.net.addSwitch('access4', protocols='OpenFlow13', failMode='secure')
        access5 = self.net.addSwitch('access5', protocols='OpenFlow13', failMode='secure')
        access6 = self.net.addSwitch('access6', protocols='OpenFlow13', failMode='secure')

        dmz_switch = self.net.addSwitch('dmz', protocols='OpenFlow13', failMode='secure')

        self.switches = {
            'core1': core1, 'core2': core2,
            'agg1': agg1, 'agg2': agg2, 'agg3': agg3,
            'access1': access1, 'access2': access2, 'access3': access3,
            'access4': access4, 'access5': access5, 'access6': access6,
            'dmz': dmz_switch
        }

        info('*** Adding internal hosts\n')
        workstations = []
        for i in range(1, 13): # workstation 1~12, 12개
            ws = self.net.addHost(f'ws{i}', ip=f'10.1.1.{i}/24', mac=f'00:00:00:01:01:{i:02x}')
            workstations.append(ws)

        web_server = self.net.addHost('web_server', ip='10.2.1.100/24', mac='00:00:00:02:01:64')
        db_server = self.net.addHost('db_server', ip='10.2.1.101/24', mac='00:00:00:02:01:65')
        file_server = self.net.addHost('file_server', ip='10.2.1.102/24', mac='00:00:00:02:01:66')
        dns_server = self.net.addHost('dns_server', ip='10.2.1.103/24', mac='00:00:00:02:01:67')
        mail_server = self.net.addHost('mail_server', ip='10.2.1.104/24', mac='00:00:00:02:01:68')

        admin_host = self.net.addHost('admin', ip='10.3.1.10/24', mac='00:00:00:03:01:0a')
        monitor_host = self.net.addHost('monitor', ip='10.30.1.20/24', mac='00:00:00:03:01:14')

        dmz_web = self.net.addHost('dmz_web', ip='192.168.1.100/24', mac='00:00:00:c0:a8:64')
        dmz_mail = self.net.addHost('dmz_mail', ip='192.168.1.101/24', mac='00:00:00:c0:a8:65')

        external1 = self.net.addHost('ext1', ip='172.16.1.10/24', mac='00:00:00:ac:10:0a')
        external2 = self.net.addHost('ext2', ip='172.16.1.11/24', mac='00:00:00:ac:10:0b')
        attacker1 = self.net.addHost('attacker1', ip='172.16.2.100/24', mac='00:00:00:ac:10:64')
        attacker2 = self.net.addHost('attacker2', ip='172.16.2.101/24', mac='00:00:00:ac:10:65')

        self.hosts = {
            'workstations': workstations,
            'servers': [web_server, db_server, file_server, dns_server, mail_server],
            'management': [admin_host, monitor_host],
            'dmz': [dmz_web, dmz_mail],
            'external': [external1, external2],
            'attackers': [attacker1, attacker2]
        }
        
        info('*** Adding links\n')
        self.create_topology_links()
        self.connect_hosts_to_switches()

        return self.net
    
    def create_topology_links(self): # 링크 연결
        self.net.addLink('core1', 'core2', bw=1000, delay='1ms') # 코어 스위치간

        # core1- {agg1, agg2} , core2- {agg2, agg3}
        self.net.addLink('core1', 'agg1', bw=1000, delay='2ms')
        self.net.addLink('core1', 'agg2', bw=1000, delay='2ms')
        self.net.addLink('core2', 'agg2', bw=1000, delay='2ms')
        self.net.addLink('core2', 'agg3', bw=1000, delay='2ms')

        # agg1- {access1, access2} , agg2- {access3, access4} , agg3- {access5, access6}
        self.net.addLink('agg1', 'access1', bw=100, delay='5ms')
        self.net.addLink('agg1', 'access2', bw=100, delay='5ms')
        self.net.addLink('agg2', 'access3', bw=100, delay='5ms')
        self.net.addLink('agg2', 'access4', bw=100, delay='5ms')
        self.net.addLink('agg3', 'access5', bw=100, delay='5ms')
        self.net.addLink('agg3', 'access6', bw=100, delay='5ms')

        # dmz 연결
        self.net.addLink('core1', 'dmz', bw=100, delay='3ms')

        # agg1 - agg2 , agg2 - agg3  리던던시
        self.net.addLink('agg1', 'agg2', bw=100, delay='5ms')
        self.net.addLink('agg2', 'agg3', bw=100, delay='5ms')

    def connect_hosts_to_switches(self): # 호스트-스위치 링크 연결
        workstations = self.hosts['workstations']
        access_switches = ['access1', 'access2', 'access3', 'access4', 'access5', 'access6']

        for i, ws in enumerate(workstations):
            switch = access_switches[i // 2] # ws1~2 => access1 , 3~4 => access2 ... 11~12 => access6
            self.net.addLink(ws, switch, bw=10, delay='1ms')

        # server - aggregation switch
        servers = self.hosts['servers']
        server_switches = ['agg1', 'agg1', 'agg2', 'agg2', 'agg3']

        for server, switch in zip(servers, server_switches):
            self.net.addLink(server, switch, bw=100, delay='1ms')
        
        # management host - core2
        for mgmt_host in self.hosts['management']:
            self.net.addLink(mgmt_host, 'core2', bw=10, delay='1ms')

        for dmz_host in self.hosts['dmz']:
            self.net.addLink(dmz_host, 'dmz', bw=50, delay='1ms')

        for ext_host in self.hosts['external'] + self.hosts['attackers']:
            self.net.addLink(ext_host, 'core1', bw=10, delay='20ms', loss=1) # 내부망이 아닌 외부 연결 -> loss=1:손실 1%, delay='20ms':지연 20ms로 설정

    def setup_host_services(self): 
        info('*** Setting up host services\n')

        # Web server 부
        web_server = None
        for server in self.hosts['servers']:
            if 'web_server' in str(server):
                web_server = server
                break

        if web_server:
            web_server.cmd('echo "Welcome to Enterprise Web Server" > /tmp/index.html')
            web_server.cmd('cd /tmp && python3 -m http.server 80 &')
            # web_server.cmd('python3 -m http.server 443 &') // 중복실행 포트 충돌 가능성 (checkThis)
        
        # DB server 부
        db_server = None
        for server in self.hosts['servers']:
            if 'db_server' in str(server):
                db_server = server
                break
        
        if db_server:
            db_server.cmd('nc -l -p 3306 &')
            db_server.cmd('nc -l -p 5432 &')
        
        # File server 부
        file_server = None
        for server in self.hosts['servers']:
            if 'file_server' in str(server):
                file_server = server
                break
        
        if file_server:
            file_server.cmd('nc -l -p 445 &')
            file_server.cmd('nc -l -p 21 &')
            file_server.cmd('nc -l -p 22 &')
        
        # DNS server 부
        dns_server = None
        for server in self.hosts['servers']:
            if 'dns_server' in str(server):
                dns_server = server
                break
        
        if dns_server:
            dns_server.cmd('nc -l -u -p 53 &')
        
        # Mail server 부
        mail_server = None
        for server in self.hosts['servers']:
            if 'mail_server' in str(server):
                mail_server = server
                break
        
        if mail_server:
            mail_server.cmd('nc -l -p 25 &')
            mail_server.cmd('nc -l -p 110 &')
            mail_server.cmd('nc -l -p 143 &')

        # DMZ service 부
        for dmz_host in self.hosts['dmz']:
            if 'dmz_web' in str(dmz_host):
                dmz_host.cmd('echo "DMZ Web Server" > /tmp/dmz_index.html')
                dmz_host.cmd('cd /tmp && python3 -m http.server 80 &')
            elif 'dmz_mail' in str(dmz_host):
                dmz_host.cmd('nc -l -p 25 &')
        
        time.sleep(2)
        info('*** Services started\n')

    def create_simple_topology(self): # Test 용
        info('*** Creating Simple Test Topology\n')

        self.net = Mininet(
            topo=None,
            build=False,
            ipBase='10.0.1.0/24',
            link=TCLink,
            autoSetMacs=True
        )        

        controller = self.net.addController(
            'c0',
            controller=RemoteController,
            ip=self.controller_ip,
            port=self.controller_port,
            protocols='OpenFlow13'
        )

        s1 = self.net.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.net.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.net.addSwitch('s3', protocols='OpenFlow13')

        client1 = self.net.addHost('client1', ip='10.0.1.10/24')
        client2 = self.net.addHost('client2', ip='10.0.1.11/24')
        client3 = self.net.addHost('client3', ip='10.0.1.12/24')

        web_server = self.net.addHost('web_server', ip='10.0.1.100/24')
        db_server = self.net.addHost('db_server', ip='10.0.1.101/24')

        attacker1 = self.net.addHost('attacker1', ip='10.0.1.200/24')
        attacker2 = self.net.addHost('attacker2', ip='10.0.1.201/24')

        monitor = self.net.addHost('monitor', ip='10.0.1.250/24')

        self.net.addLink(s1, s2, bw=100)
        self.net.addLink(s1, s3, bw=100)
        self.net.addLink(s2, s3, bw=50)

        self.net.addLink(client1, s1, bw=10)
        self.net.addLink(client2, s1, bw=10)
        self.net.addLink(client3, s2, bw=10)

        self.net.addLink(web_server, s2, bw=50)
        self.net.addLink(db_server, s2, bw=50)

        self.net.addLink(attacker1, s3, bw=20)
        self.net.addLink(attacker2, s3, bw=20)

        self.net.addLink(monitor, s1, bw=100)

        self.hosts = {
            'client': [client1, client2, client3],
            'server': [web_server, db_server],
            'attackers': [attacker1, attacker2],
            'monitor': [monitor]
        }

        return self.net
    
    def run_connectivity_tests(self): 
        info('*** Running connectivity tests\n')

        if 'workstations' in self.hosts and 'servers' in self.hosts:
            client = self.hosts['workstations'][0]
            server = self.hosts['servers'][0]

            info('*** Testing client to server connectivity\n')
            result = client.cmd(f'ping -c 3 {server.IP()}')
            if '3 received' in result: info('Internal connectivity: PASS\n')
            else: info('Internal connectivity: FAIL\n')

        if 'servers' in self.hosts:
            web_server = None
            for server in self.hosts['servers']:
                if 'web_server' in str(server):
                    web_server = server
                    break
            
            if web_server and 'workstations' in self.hosts:
                client = self.hosts['workstations'][0]
                info('*** Testing web service\n')
                result = client.cmd(f'curl -m 5 http://{web_server.IP()}/')
                if 'Enterprise Web Server' in result: info('Web service: PASS\n')
                else: info('Web service: FAIL\n')
    
    def generate_normal_traffic(self, duration=60): 
        info(f'*** Generating normal traffic for {duration} seconds\n')

        def client_traffic(): # traffic_thread 실행 함수
            if 'workstations' in self.hosts and 'servers' in self.hosts:
                clients = self.hosts['workstations']
                servers = self.hosts['servers']

                import random
                end_time = time.time() + duration

                while time.time() < end_time:
                    client = random.choice(clients)
                    server = random.choice(servers)

                    if 'web_server' in str(server): client.cmd(f'curl -s {server.IP()} > /dev/null &')
                    elif 'db_server' in str(server): client.cmd(f'nc -w 1 {server.IP()} 3306 < /dev/null &')
                    elif 'file_server' in str(server): client.cmd(f'nc -w 1 {server.IP()} 445 < /dev/null &')

                    time.sleep(random.uniform(1, 5))
        
        traffic_thread = threading.Thread(target=client_traffic)
        traffic_thread.daemon = True
        traffic_thread.start()

        return traffic_thread

    def open_terminals(self): 
        info('*** Opening terminals\n')

        terminals = []
        # 모니터
        if 'management' in self.hosts: 
            monitor = self.hosts['management'][1]
            terminals.append(makeTerm(monitor, title='Monitor', term='xterm'))
        elif 'monitor' in self.hosts:
            monitor = self.hosts['monitor'][0]
            terminals.append(makeTerm(monitor, title='Monitor', term='xterm'))
        # 공격자
        if 'attackers' in self.hosts:
            for i, attacker in enumerate(self.hosts['attackers']):
                terminals.append(makeTerm(attacker, title=f'Attacker{i+1}', term='xterm'))
        # 서버
        if 'servers' in self.hosts:
            server = self.hosts['servers'][0]
            terminals.append(makeTerm(server, title='Webserver', term='xterm'))
        # 어드민
        if 'management' in self.hosts:
            admin = self.hosts['management'][0]
            terminals.append(makeTerm(admin, title='Admin', term='xterm'))
        
        self.net.terms.extend(terminals)
        info(f'*** Opened {len(terminals)} terminals\n')
    
    def install_attack_tools(self): 
        info('*** Installing attack tools\n')

        attack_tools = [
            'hping3', 'nmap', 'netcat-openbsd', 'curl', 'wget',
            'tcpdump', 'wireshark-common'
        ]

        if 'attackers' in self.hosts:
            for attacker in self.hosts['attackers']:
                info(f'*** Installing tools on {attacker.name}\n')
                attacker.cmd('echo "Attack tools ready" > /tmp/tools_ready')
        
        script_dir = 'src/network'
        if os.path.exists(script_dir):
            for attacker in self.hosts.get('attackers', []):
                attacker.cmd(f'mkdir -p /tmp/attack_scripts')
                if os.path.exists(os.path.join(script_dir, 'attack_simulator_enhanced.py')):
                    attacker.cmd('echo "# Attack simulator script" > /tmp/attack_scripts/attack_sim.py')
    
    def show_network_info(self): 
        info('*** Network Information\n')
        info('*** Switches:\n')
        for name, switch in self.switches.items():
            info(f'    {name}: {switch.IP() if hasattr(switch, "IP") else "N/A"}\n')

        info('*** Hosts by Category:\n')
        for category, hosts in self.hosts.items():
            info(f'    {category.upper()}:\n')
            for host in hosts:
                info(f'    {host.name}: {host.IP()}\n')
        
        info('*** Controller: {}:{}\n'.format(self.controller_ip, self.controller_port))
            # dk for tq

    def start_network(self, topology_type='enterprise'): 
        try:
            if topology_type == 'enterprise': net = self.create_enterprise_topology()
            else: net = self.create_simple_topology()
            
            info('*** Building network\n')
            net.build()

            info('*** Starting network\n')
            net.start()
        
            info('*** Waiting for controller connection\n')
            time.sleep(5)

            self.setup_host_services()
            self.run_connectivity_tests()
            self.install_attack_tools()
            self.show_network_info()
            self.open_terminals()

            info('*** Starting background normal traffic\n')
            self.generate_normal_traffic(duration=3600) # 1h

            info('*** Network ready for testing\n')
            info('*** Use the following commands:\n')
            info('    - pingall: Test connectivity\n')
            info('    - iperf: Test bandwidth\n')
            info('    - dump: Show network topology\n')
            info('    - py <python_code>: Execute Python code\n')
            info('*** To run attacks, use the attacker terminals\n')

            return net
        except Exception as e:
            error(f'*** Error starting network: {e}\n')
            if self.net: self.net.stop()
            return None

    def stop_network(self): 
        if self.net:
            info('*** Stopping network\n')
            self.net.stop()

class NetworkTestRunner:
    def __init__(self, topology): 
        self.topology = topology
        self.test_results = {}

    def run_performance_tests(self):
        info('*** Running performance tests\n')

        net = self.topology.net
        if not net: return

        # 벤드위쓰 ㅌㅅㅌ
        hosts = self.topology.hosts
        if 'workstations' in hosts and 'servers' in hosts:
            client = hosts['workstations'][0]
            server = hosts['servers'][0]

            info('*** Testing bandwidth\n')
            server.cmd('iperf -s &')
            time.sleep(1)
            result = client.cmd(f'iperf -c {server.IP()} -t 10')
            self.test_results['bandwidth'] = result
            server.cmd('pkill iperf')
        
        # 레이턴시 ㅌㅅㅌ
        if 'workstations' in hosts and 'servers' in hosts:
            client = hosts['workstations'][0]
            server = hosts['servers'][0]

            info('*** Testing latency\n')
            result = client.cmd(f'ping -c 10 {server.IP()}')
            self.test_results['latency'] = result
        
        return self.test_results

    def run_security_tests(self): 
        info('*** Running security tests\n')

        hosts = self.topology.hosts
        if 'attackers' in hosts and 'servers' in hosts:
            attacker = hosts['attackers'][0]
            server = hosts['servers'][0]

            info('*** Testing port scan detection\n')
            result = attacker.cmd(f'nc -zv {server.IP()} 1-100 2>&1')
            self.test_results['port_scan'] = result

            info('*** Testing connection flood\n')
            result = attacker.cmd(f'for i in {{1..50}}; do nc -w 1 {server.IP()} 80 & done; wait')
            self.test_results['connection_flood'] = result

        return self.test_results

def main(): 
    parser = argparse.ArgumentParser(description='Network Topology for ML-SDN Defense')
    parser.add_argument('--topology', choices=['enterprise', 'simple'], default='enterprise', help='Topology type')
    parser.add_argument('--controller-ip', default='127.0.0.1', help='Controller IP address')
    parser.add_argument('--controller-port', type=int, default=6653, help='Controller port')
    parser.add_argument('--test', action='store_true', help='Run automated tests')
    parser.add_argument('--duration', type=int, default=0, help='Auto-stop after duration (seconds)')
    
    args = parser.parse_args()

    if os.geteuid() != 0:
        error('*** This script must be run as root\n')
        return
    
    setLogLevel('info')

    topology = NetworkTopology(args.controller_ip, args.controller_port)

    try:
        net = topology.start_network(args.topology)

        if not net:
            error('*** Failed to start network\n')
            return
        
        if args.test:
            test_runner = NetworkTestRunner(topology)
            perf_results = test_runner.run_performance_tests()
            sec_results = test_runner.run_security_tests()

            info('*** Test Results:\n')
            for test_name, result in {**perf_results, **sec_results}.items():
                info(f'{test_name}: {result[:100]} ...\n')
        
        if args.duration > 0:
            info(f'*** Running for {args.duration} seconds\n')
            time.sleep(args.duration)
        else:
            info('*** Starting CLI (type "exit" to stop)\n')
            CLI(net)
    except KeyboardInterrupt:
        info('*** Interrupted by user\n')
    except Exception as e:
        error(f'*** error: {e}\n')
    finally:
        topology.stop_network()
        info('*** Network stopped\n')

if __name__ == '__main__': main()