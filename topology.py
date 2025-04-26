#!/usr/bin/python
 
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import Controller 
from mininet.cli import CLI
from functools import partial
from mininet.node import RemoteController
import os

class MyTopo(Topo):
    """ So, for example, you can set: self.addLink(s1, s2, port1=10, port2=20, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True) """
           
    def __init__(self):
        Topo.__init__(self)
        s1=self.addSwitch('s1')
        s2=self.addSwitch('s2')
        s3=self.addSwitch('s3')
        s4=self.addSwitch('s4')
        s5=self.addSwitch('s5')
        h1=self.addHost('h1')
        h2=self.addHost('h2')
        h3=self.addHost('h3')
        h4=self.addHost('h4')
        h5=self.addHost('h5')
        h6=self.addHost('h6')

        self.addLink(h1, s1, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(h2, s1, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(h3, s1, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s1, s2, bw=1, delay='200ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s1, s3, bw=1, delay='50ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s1, s4, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s2, s5, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s3, s5, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s4, s5, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s5, h4, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s5, h5, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s5, h6, bw=1, delay='0ms', loss=0, max_queue_size=1000, use_htb=True)

def perfTest():
    topo = MyTopo()
    #net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=POXcontroller1)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=partial(RemoteController, ip='192.168.1.142', port=6633))
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    h1,h2,h3,h4,h5,h6=net.get('h1','h2','h3','h4','h5','h6')
    h1.setMAC("0:0:0:0:0:1")
    h2.setMAC("0:0:0:0:0:2")
    h3.setMAC("0:0:0:0:0:3")
    h4.setMAC("0:0:0:0:0:4")
    h5.setMAC("0:0:0:0:0:5")
    h6.setMAC("0:0:0:0:0:6")
    s1,s2,s3,s4,s5=net.get('s1','s2','s3','s4','s5')
    s1.cmd('ifconfig s1-eth1 hw ether 0:0:0:0:1:1')
    s1.cmd('ifconfig s1-eth2 hw ether 0:0:0:0:1:2')
    s1.cmd('ifconfig s1-eth3 hw ether 0:0:0:0:1:3')
    s1.cmd('ifconfig s1-eth4 hw ether 0:0:0:0:1:4')
    s1.cmd('ifconfig s1-eth5 hw ether 0:0:0:0:1:5')
    s1.cmd('ifconfig s1-eth6 hw ether 0:0:0:0:1:6')
    s2.cmd('ifconfig s2-eth1 hw ether 0:0:0:0:2:1')
    s2.cmd('ifconfig s2-eth2 hw ether 0:0:0:0:2:2')
    s3.cmd('ifconfig s3-eth1 hw ether 0:0:0:0:3:1')
    s3.cmd('ifconfig s3-eth2 hw ether 0:0:0:0:3:2')
    s4.cmd('ifconfig s4-eth1 hw ether 0:0:0:0:4:1')
    s4.cmd('ifconfig s4-eth2 hw ether 0:0:0:0:4:2')
    s5.cmd('ifconfig s5-eth1 hw ether 0:0:0:0:5:1')
    s5.cmd('ifconfig s5-eth2 hw ether 0:0:0:0:5:2')
    s5.cmd('ifconfig s5-eth3 hw ether 0:0:0:0:5:3')
    s5.cmd('ifconfig s5-eth4 hw ether 0:0:0:0:5:4')
    s5.cmd('ifconfig s5-eth5 hw ether 0:0:0:0:5:5')
    s5.cmd('ifconfig s5-eth6 hw ether 0:0:0:0:5:6')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    perfTest()
