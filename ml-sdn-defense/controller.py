#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, ether_types
from ryu.lib import hub

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from network.packet_collector import PacketCollector
from network.flow_manager import FlowManager
from monitoring.attack_monitor import AttackMonitor

import logging

class SDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)
       
        self.logger.setLevel(logging.INFO)
       
        self.mac_to_port = {}
        self.datapaths = {}
       
        self.monitored_ports = {
            22,   # SSH
            23,   # Telnet
            80,   # HTTP
            443,  # HTTPS
            3389, # RDP
            8080, # HTTP alt
        }
       
        # 카운터
        self.packet_count = 0
        self.analyzed_count = 0
        self.bypassed_count = 0
       
        # 컴포넌트 초기화
        try:
            self.packet_collector = PacketCollector(
                ml_model_path='data/models/best_model.pkl',
                scaler_path='data/processed/cicids2017/scaler.pkl',
                attack_threshold=0.7
            )
            self.logger.info("✓ PacketCollector initialized")
        except Exception as e:
            self.logger.error(f"✗ PacketCollector failed: {e}")
            raise
       
        self.flow_manager = FlowManager()
        self.attack_monitor = AttackMonitor(log_dir='logs/attacks')
       
        # 주기적 작업
        self.cleanup_thread = hub.spawn(self._periodic_cleanup)
        self.stats_thread = hub.spawn(self._periodic_stats)
       
        self.logger.info("="*80)
        self.logger.info("SDN Attack Defense - SELECTIVE ANALYSIS MODE")
        self.logger.info(f"Monitored ports: {sorted(self.monitored_ports)}")
        self.logger.info("ICMP and suspicious traffic will be analyzed")
        self.logger.info("⚠️  Flow rules will NOT be installed for monitored traffic")
        self.logger.info("="*80)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """스위치 초기 설정"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.logger.info(f"🔌 Switch connected: DPID={datapath.id}")

        # Table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0):
        """Flow 추가"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
       
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
       
        datapath.send_msg(mod)

    def should_analyze(self, packet_info):
        # ICMP 항상 (ping flood 탐지)
        if packet_info.get('protocol') == 1:  # ICMP
            return True
       
        # 모니터링 포트 체크
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
       
        if dst_port in self.monitored_ports or src_port in self.monitored_ports:
            return True
       
        # 낮은 포트 번호 (privilege ports)
        if 0 < dst_port < 1024:
            return True
       
        return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        self.packet_count += 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # MAC 학습
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # 패킷 정보 추출
        packet_info = self.extract_packet_info(pkt, in_port, dpid)

        # 분석 필요 여부 플래그
        needs_analysis = False
       
        # IP 패킷 분석
        if 'src_ip' in packet_info and 'dst_ip' in packet_info:
           
            if self.flow_manager.is_ip_blocked(packet_info['src_ip']):
                self.logger.debug(f"Blocked: {packet_info['src_ip']}")
                return
           
            if self.should_analyze(packet_info):
                needs_analysis = True
                self.analyzed_count += 1
               
                # 디버그 로그
                if self.analyzed_count % 20 == 1:
                    self.logger.info(
                        f"📦 Analyzing #{self.analyzed_count}: "
                        f"{packet_info['src_ip']}:{packet_info.get('src_port', 0)} -> "
                        f"{packet_info['dst_ip']}:{packet_info.get('dst_port', 0)} "
                        f"(proto={packet_info.get('protocol')})"
                    )
               
                try:
                    is_attack, attack_type, confidence = self.packet_collector.analyze_packet(packet_info)
                   
                    if is_attack:
                        self.logger.warning(
                            f"🚨 ATTACK! {attack_type} "
                            f"[{packet_info['src_ip']}:{packet_info.get('src_port', 0)} -> "
                            f"{packet_info['dst_ip']}:{packet_info.get('dst_port', 0)}] "
                            f"Confidence: {confidence:.2%}"
                        )
                       
                        self.attack_monitor.log_attack(packet_info, attack_type, confidence)
                        self.block_attack(datapath, packet_info, attack_type)
                        return
                       
                except Exception as e:
                    self.logger.error(f"❌ Analysis failed: {e}")
            else:
                self.bypassed_count += 1

        # 정상 패킷 전달
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # 분석 대상 트래픽은 Flow Rule 설치하지 않음
        # 모든 패킷을 컨트롤러로 계속 보내서 분석하기 위함
        should_install_flow = True
        if needs_analysis:
            should_install_flow = False  # Flow Rule 설치 안 함
            self.logger.debug(f"Skipping flow installation for monitored traffic: {packet_info.get('src_ip')}")
       
        # 플로우 설치 (정상 트래픽만)
        if should_install_flow and out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
           
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=10)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=10)

        # 패킷 전송 (분석 대상 트래픽 or Flood)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def extract_packet_info(self, pkt, in_port, dpid):
        """패킷 정보 추출"""
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        packet_info = {
            'dpid': dpid,
            'in_port': in_port,
            'src_mac': eth.src,
            'dst_mac': eth.dst,
            'eth_type': eth.ethertype,
            'packet_size': len(pkt.data) if hasattr(pkt, 'data') else 0
        }

        if ipv4_pkt:
            packet_info.update({
                'src_ip': ipv4_pkt.src,
                'dst_ip': ipv4_pkt.dst,
                'protocol': ipv4_pkt.proto,
                'ttl': ipv4_pkt.ttl
            })
           
            if tcp_pkt:
                packet_info.update({
                    'src_port': tcp_pkt.src_port,
                    'dst_port': tcp_pkt.dst_port,
                    'tcp_flags': tcp_pkt.bits
                })
            elif udp_pkt:
                packet_info.update({
                    'src_port': udp_pkt.src_port,
                    'dst_port': udp_pkt.dst_port,
                    'tcp_flags': 0
                })
            elif icmp_pkt:
                packet_info.update({
                    'src_port': 0,
                    'dst_port': 0,
                    'tcp_flags': 0,
                    'icmp_type': icmp_pkt.type
                })
            else:
                packet_info.update({
                    'src_port': 0,
                    'dst_port': 0,
                    'tcp_flags': 0
                })

        return packet_info

    def block_attack(self, datapath, packet_info, attack_type):
        """공격 차단"""
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return
       
        self.flow_manager.block_ip(datapath, src_ip, duration=300)
       
        self.logger.info(f"🔒 BLOCKED: {src_ip} ({attack_type}, 300s)")
        self.attack_monitor.update_blocked_count(src_ip, attack_type)

    def _periodic_cleanup(self):
        """정리"""
        while True:
            hub.sleep(300)
           
            try:
                self.packet_collector.cleanup_old_flows(max_age=300)
                self.flow_manager.cleanup_expired_blocks(self.datapaths)
                self.logger.info("🧹 Cleanup done")
            except Exception as e:
                self.logger.error(f"Cleanup error: {e}")

    def _periodic_stats(self):
        """통계"""
        while True:
            hub.sleep(30)
           
            try:
                pkt_stats = self.packet_collector.get_statistics()
                flow_stats = self.flow_manager.get_flow_stats()
               
                analysis_rate = self.analyzed_count / max(self.packet_count, 1)
               
                self.logger.info(
                    f"📊 Packets - Total: {self.packet_count}, "
                    f"Analyzed: {self.analyzed_count} ({analysis_rate:.1%}), "
                    f"Bypassed: {self.bypassed_count}"
                )
               
                self.logger.info(
                    f"📊 ML - Pkts: {pkt_stats['total_packets']}, "
                    f"Attacks: {pkt_stats['total_attacks']}, "
                    f"Rate: {pkt_stats['attack_rate']:.2%}, "
                    f"Flows: {pkt_stats['active_flows']}"
                )
               
                self.logger.info(f"📊 Blocked IPs: {flow_stats['blocked_ips']}")
               
                if pkt_stats['attacks_by_type']:
                    self.logger.info(f"🎯 Attacks: {pkt_stats['attacks_by_type']}")
               
            except Exception as e:
                self.logger.error(f"Stats error: {e}")

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """포트 상태"""
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        reason_map = {
            ofp.OFPPR_ADD: 'ADD',
            ofp.OFPPR_DELETE: 'DELETE',
            ofp.OFPPR_MODIFY: 'MODIFY'
        }
       
        reason = reason_map.get(msg.reason, 'UNKNOWN')
        self.logger.info(f"Port: DPID={dp.id}, Port={msg.desc.port_no}, {reason}")
