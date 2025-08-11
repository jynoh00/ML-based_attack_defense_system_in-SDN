#!/usr/bin/env python3
# SDN Controller (network management, traffic monitoring)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
import time
import json
from collections import defaultdict, deque

class NetworkController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs): # **kwargs?
        super(NetworkController, self).__init__(*args, **kwargs)

        #MAC learning table
        self.mac_to_port = {}

        #Traffic monitoring
        self.flow_stats = defaultdict(lambda: defaultdict(int))
        self.packet_count = defaultdict(int)
        self.byte_count = defaultdict(int)

        self.suspicious_ips = set()
        self.connection_tracker = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_tracker = defaultdict(set)

        self.DDOS_THRESHOLD = 1000
        self.PORT_SCAN_THRESHOLD = 10
        self.TIME_WINDOW = 60

        self.logger.info('Network Controller initialized')
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info('Switch connected: %s', datapath.id)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = ofproto.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def block_ip(self, datapath, src_ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []
        self.add_flow(datapath, 1000, match, actions, hard_timeout=300)

        self.logger.warning("BLOCKED IP: $s for 5 minutes", src_ip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = ofproto.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        current_time = time.time()
        self.analyze_traffic(pkt, current_time, datapath)

        if dst in self.mac_to_port[dpid]: out_port = self.mac_to_port[dpid][dst]
        else: out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else: self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def analyze_traffic(self, pkt, current_time, datapath):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt: return

        src_ip = ip_pkt.src; dst_ip = ip_pkt.dst; protocol = ip_pkt.proto

        self.packet_count[src_ip] += 1
        self.connection_tracker[src_ip].append(current_time)

        self.detect_ddos(src_ip, current_time, datapath)

        if protocol == 6:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt: self.detect_port_scan(src_ip, dst_ip, tcp_pkt.dst_port, datapath)

        if src_ip in self.suspicious_ips:
            self.logger.warning('Packet from suspicious IP %s to %s', src_ip, dst_ip)

    def detect_ddos(self, src_ip, current_time, datapath):
        connections = self.connection_tracker[src_ip]

        while connections and current_time - connections[0] > self.TIME_WINDOW: connections.popleft()
        
        if len(connections) > self.DDOS_THRESHOLD:
            if src_ip not in self.suspicious_ips:
                self.suspicious_ips.add(src_ip)
                self.logger.warning('DDOS DETECTED from IP: %s (Rate %d pkt/m)', src_ip, len(connections))
                self.block_ip(datapath, src_ip)
    
    def detect_port_scan(self, src_ip, dst_ip, dst_port, datapath):
        scan_key = f'{src_ip}->{dst_ip}'
        self.port_scan_tracker[scan_key].add(dst_port)

        unique_ports = len(self.port_scan_tracker[scan_key])

        if unique_ports > self.PORT_SCAN_THRESHOLD:
            if src_ip not in self.suspicious_ips:
                self.suspicious_ips.add(src_ip)
                self.logger.warning("PORT SCAN DETECTED from %s to %s (%d unique ports)", src_ip, dst_ip, unique_ports)

                self.block_ip(datapath, src_ip)
    
    def get_traffic_stats(self):
        stats = {
            'total_packets': sum(self.packet_count.values()),
            'suspicious_ips': list(self.suspicious_ips),
            'top_talkers': sorted(self.packet_count.items(), key=lambda x: x[1], reverse=True)[:10] # x[0]아닌가?
        }
        return stats

    def reset_suspicious_ips(self):
        self.suspicious_ips.clear()
        self.logger.info("Suspicious IP list cleared")

if __name__ == '__main__': pass