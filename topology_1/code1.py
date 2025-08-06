#!/usr/bin/python
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
    net.build()

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    h1.setMAC(intf='client-eth0', mac = "00:00:00:00:00:03")
    h2.setMAC(intf='server1-eth0', mac = "00:00:00:00:00:01")
    h3.setMAC(intf='server2-eth0', mac = "00:00:00:00:00:02")

    h1.setIP(intf='client-eth0', ip='10.0.1.5/24')
    h2.setIP(intf='server1-eth0', ip='10.0.1.2/24')
    h3.setIP(intf='server2-eth0', ip='10.0.1.3/24')

    net.start() # <

    net.terms += makeTerm(c1)
    net.terms += makeTerm(h1)
    net.terms += makeTerm(h2)
    net.terms += makeTerm(h3)

    CLI(net) # >

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myTopo()



#/usr/bin/python

### < Library
# from mininet.net import Mininet
# from mininet.cli import CLI
# from mininet.node import Host
# from mininet.node import OVSKernelSwitch
# from mininet.log import setLogLevel, info
# from mininet.node import RemoteController
# from mininet.term import makeTerm
### >

# def myTopo():
#     net = Mininet(topo=None, autoSetMacs=False, build=False, ipBase='10.0.1.0/24')
    
#     h1 = net.addHost('client', cls=Host, defaultRoute=None)
#     h2 = net.addHost('server1', cls=Host, defaultRoute=None)
#     h3 = net.addHost('server2', cls=Host, defaultRoute=None)

#     c1 = net.addController('c1', RemoteController)
#     s1 = net.addSwitch('s1', protocols='OpenFlow13', failMode='standalone')
    
#     net.build()



# Host Number : 3 (client 1, server 2)
# Controller Number : 1
# Switch Number : 1


# from mininet.net import Mininet
# from mininet.topo import Topo
# from mininet.node import OVSController
# from mininet.log import setLogLevel

# class SimpleTopo(Topo):
#     def build(self):
#         switch = self.addSwitch('s1')

#         host1 = self.addHost('h1')
#         host2 = self.addHost('h2')

#         self.addLink(host1, switch)
#         self.addLink(host2, switch)

# def run():
#     topo = SimpleTopo()
#     net = Mininet(topo=topo, controller=OVSController)

#     net.start()

#     print("Network hosts:", net.hosts)

#     net.pingAll()
#     net.stop()

# setLogLevel('info')

# run()