#!/usr/bin/python
# 0805 code1.py modify
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm

def myTopo():
    net = Mininet(topo=None, autoSetMacs=False, build=False, ipBase='10.0.1.0/24')

    h1 = net.addHost('client', cls=Host, defaultRoute=None)
    h2 = net.addHost('server1', cls=Host, defaultRoute=None)
    h3 = net.addHost('server2', cls=Host, defaultRoute=None)

    c1 = net.addController('c1', RemoteController)
    s1 = net.addSwitch('s1', protocols='OpenFlow13', failMode='standalone')

    net.addLink(h1, s1); net.addLink(h2, s1); net.addLink(h3, s1)

    net.build() # Link 연결 이후, build

    h1.setMAC(intf='client-eth0', mac='00:00:00:00:00:03')
    h2.setMAC(intf='server1-eth0', mac='00:00:00:00:00:01')
    h3.setMAC(intf='server2-eth0', mac='00:00:00:00:00:02')

    h1.setIP(intf='client-eth0', ip='10.0.1.5/24')
    h2.setIP(intf='server1-eth0', ip='10.0.1.2/24')
    h3.setIP(intf='server2-eth0', ip='10.0.1.3/24')

    net.start()

    # 각 터미널 개별 open
    net.terms += makeTerm(c1); net.terms += makeTerm(h1)
    net.terms += makeTerm(h2); net.terms += makeTerm(h3)

    CLI(net) # Command Line Interface start, net: 네트워크 객체

    net.stop()

if __name__ == '__main__': setLogLevel('info'); myTopo
