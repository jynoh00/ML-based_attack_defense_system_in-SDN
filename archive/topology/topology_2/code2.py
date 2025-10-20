#!/usr/bin/python3
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm
from mininet.link import TCLink
import time

def create_myTopo():
    net = Mininet(topo=None, autoSetMacs=False, build=False, ipBase='10.0.1.0/24', link=TCLink)

    info('[sys] Adding controller\n')
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653, protocols='OpenFlow13')

    info('[sys] Adding switches\n')
    s0 = net.addSwitch('s0', protocols='OpenFlow13')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    info('[sys] Adding hosts\n')
    client0 = net.addHost('client0', cls=Host, ip='10.0.1.10/24', defaultRoute=None)
    client1 = net.addHost('client1', cls=Host, ip='10.0.1.11/24', defaultRoute=None)
    client2 = net.addHost('client2', cls=Host, ip='10.0.1.12/24', defaultRoute=None)

    web_server = net.addHost('web_server', cls=Host, ip='10.0.1.100/24', defaultRoute=None)
    db_server = net.addHost('db_server', cls=Host, ip='10.0.1.101/24', defaultRoute=None)
    dns_server = net.addHost('dns_server', cls=Host, ip='10.0.1.102/24', defaultRoute=None)

    attacker0 = net.addHost('attacker0', cls=Host, ip='10.0.1.200/24', defaultRoute=None)
    attacker1 = net.addHost('attacker1', cls=Host, ip='10.0.1.201/24', defaultRoute=None)

    monitor = net.addHost('monitor', cls=Host, ip='10.0.1.250/24', defaultRoute=None)

    info('[sys] Creating links\n')
    net.addLink(s0, s1, bw=100); net.addLink(s0, s2, bw=100)
    net.addLink(client0, s1, bw=10); net.addLink(client1, s1, bw=10); net.addLink(client2, s1, bw=10)
    net.addLink(web_server, s2, bw=50); net.addLink(db_server, s2, bw=50); net.addLink(dns_server, s2, bw=20)
    net.addLink(attacker0, s0, bw=20); net.addLink(attacker1, s0, bw=20)
    net.addLink(monitor, s0, bw=100)

    info('[sys] Configuring hosts\n')
    client0.setMAC(intf='client0-eth0', mac='00:00:00:00:01:10')
    client1.setMAC(intf='client1-eth0', mac='00:00:00:00:01:11')
    client2.setMAC(intf='client2-eth0', mac='00:00:00:00:01:12')

    web_server.setMAC(intf='web_server-eth0', mac='00:00:00:00:01:00')
    db_server.setMAC(intf='db_server-eth0', mac='00:00:00:00:01:01')
    dns_server.setMAC(intf='dns_server-eth0', mac='00:00:00:00:01:02')

    attacker0.setMAC(intf='attacker0-eth0', mac='00:00:00:00:02:00')
    attacker1.setMAC(intf='attacker1-eth0', mac='00:00:00:00:02:01')

    monitor.setMAC(intf='monitor-eth0', mac='00:00:00:00:00:01')

    setUp_server(net)

    info('[sys] Opening terminals for key hosts\n')
    net.terms += makeTerm(monitor, title="Monitor", term="xterm")
    net.terms += makeTerm(attacker0, title="Attacker0", term="xterm")
    net.terms += makeTerm(web_server, title="WebServer", term="xterm")

    return net

def setUp_server(net):
    web_server = net.get('web_server')
    web_server.cmd('echo "Hello from Web Server" > /tmp/index.html')
    web_server.cmd('cd /tmp && python3 -m http.server 80 &')

    dns_server = net.get('dns_server')
    dns_server.cmd('echo "nameserver 8.8.8.8" > /etc/resolv.conf')

    db_server = net.get('db_server')
    db_server.cmd('nc -l -p 3306 &')

    info('[sys] Server services started\n')

def run_simul(net):
    info('[sys] Running connectivity tests\n')
    client0 = net.get('client0'); web_server = net.get('web_server')

    info('*** TESTING CONNECTIVITY... \n')
    res = client0.cmd('ping -c 3 10.0.1.100')
    if ('3 received' in res): info('O - Basic connectivity working\n')
    else: info('X - Connectivity issue detected\n')

    info('*** TESTING WEB SERVICE... \n')
    res = client0.cmd('curl -m 5 http://10.0.1.100/')
    if ('Hello from Web Server' in res): info('O - Web service working\n')
    else: info('X - Web service issue\n')

def main():
    setLogLevel('info')
    net = create_myTopo()

    try:
        info('[sys] Waiting for controller connection... \n')
        time.sleep(3)

        run_simul(net)

        info('[sys] Network ready for simulation\n')
        info('[sys] Available hosts: \n')
        info('    Clients: client1(10.0.1.10), client2(10.0.1.11), client3(10.0.1.12)\n')
        info('    Servers: web_server(10.0.1.100), db_server(10.0.1.101), dns_server(10.0.1.102)\n')
        info('    Attackers: attacker1(10.0.1.200), attacker2(10.0.1.201)\n')
        info('    Monitor: monitor(10.0.1.250)\n')
        info('[sys] Use CLI commands or run attack scripts\n')

        CLI(net)
    except KeyboardInterrupt:
        info('[sys] Interrupted by user\n')
    finally:
        info('[sys] Stopping network\n')
        net.stop()

if (__name__) == '__main__': main()