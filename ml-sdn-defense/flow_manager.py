#!/usr/bin/env python3

import logging
from collections import defaultdict
import time

class FlowManager:
    def __init__(self):
        """플로우 규칙 관리"""
        self.logger = logging.getLogger(__name__)
        
        # 활성 플로우 규칙
        self.active_flows = {}
        
        # 차단된 IP 목록
        self.blocked_ips = {}
        
        # 플로우 통계
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'duration': 0,
            'install_time': 0
        })

    def install_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """플로우 규칙 설치"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        
        datapath.send_msg(mod)
        
        # 플로우 추적
        flow_id = self._generate_flow_id(match)
        self.active_flows[flow_id] = {
            'datapath_id': datapath.id,
            'match': match,
            'priority': priority,
            'install_time': time.time()
        }
        
        self.logger.debug(f"Flow installed: {flow_id}")

    def remove_flow(self, datapath, match):
        """플로우 규칙 제거"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        
        datapath.send_msg(mod)
        
        flow_id = self._generate_flow_id(match)
        if flow_id in self.active_flows:
            del self.active_flows[flow_id]
        
        self.logger.debug(f"Flow removed: {flow_id}")

    def block_ip(self, datapath, src_ip, duration=300):
        """IP 주소 차단"""
        parser = datapath.ofproto_parser
        
        # IPv4 매칭
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        
        # Drop 액션 (빈 액션)
        actions = []
        
        # 높은 우선순위로 차단 규칙 설치
        self.install_flow(datapath, 100, match, actions, hard_timeout=duration)
        
        # 차단 목록에 추가
        self.blocked_ips[src_ip] = {
            'block_time': time.time(),
            'duration': duration,
            'datapath_id': datapath.id
        }
        
        self.logger.info(f"IP blocked: {src_ip} for {duration} seconds")

    def unblock_ip(self, datapath, src_ip):
        """IP 차단 해제"""
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self.remove_flow(datapath, match)
        
        if src_ip in self.blocked_ips:
            del self.blocked_ips[src_ip]
        
        self.logger.info(f"IP unblocked: {src_ip}")

    def is_ip_blocked(self, src_ip):
        """IP가 차단되었는지 확인"""
        return src_ip in self.blocked_ips

    def cleanup_expired_blocks(self, datapaths):
        """만료된 차단 규칙 정리"""
        current_time = time.time()
        expired_ips = []
        
        for ip, info in self.blocked_ips.items():
            if current_time - info['block_time'] > info['duration']:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            datapath_id = self.blocked_ips[ip]['datapath_id']
            if datapath_id in datapaths:
                self.unblock_ip(datapaths[datapath_id], ip)

    def get_flow_stats(self):
        """플로우 통계 반환"""
        return {
            'active_flows': len(self.active_flows),
            'blocked_ips': len(self.blocked_ips),
            'blocked_ip_list': list(self.blocked_ips.keys())
        }

    def _generate_flow_id(self, match):
        """플로우 ID 생성"""
        return f"{match}"