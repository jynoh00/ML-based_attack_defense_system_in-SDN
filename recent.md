# Ryu SDN Controller: network management, traffic monitoring
## /ryu_controller/code1.py
#### 20203009 JY_NOH

1. Library Import
```python
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATHCER, MAIN_DISPATCHER
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
```
> 라이브러리 및 Ryu 모듈 임포트<br>

&emsp;app_manager: Ryu 앱의 기본 클래스, Ryu 애플리케이션(NetworkController)에 RyuApp 상속<br>
&emsp;ofp_event: OpenFlow 이벤트를 수신, 스위치 연결 및 패킷 수신 등<br>
&emsp;CONFIG_DISPATCHER, MAIN_DISPATCHER: OpenFlow 스위치의 상태를 나타내는 상수 (설정 완료, 메인 상태)<br>
&emsp;set_ev_cls: 이벤트 핸들러 등록 데코레이터<br>
&emsp;ofproto_v1_3: OpenFlow 1.3 프로토콜 사용 선언<br>
&emsp;packet, ethernet, ipv4, tcp, udp, icmp, arp: 다양한 계층의 프로토콜 파서 임포트<br>
&emsp;time: 현재 시간 확인 용도, 시간 기반 감지 기능<br>
&emsp;json: API 응답 등을 처리하기 위해 json 형식 데이터 사용<br>
&emsp;defaultdict, deque: 기본값 자동 설정 딕셔너리, 덱 자료구조 임포트<br>
<br>

2. __init__()
```python
class NetworkController(app_manager.RyuApp)
```
> RyuApp을 상속하여 SDN 컨트롤러 클래스 생성
<br>

```python
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] # OpenFlow1.3 사용 명시

def __init__(self, *args, **kwargs):
    super(NetworkController, self).__init__(*args, **kwargs)

    self.mac_to_port = {}

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
```
> NetworkController 클래스의 초기화 메서드<br>

&emsp;super().__init__()으로 부모 클래스 초기화를 실행<br>
&emsp;mac_to_port: 스위치 ID별 MAC 주소를 포트로 매핑<br>
&emsp;flow_stats: 플로우 단위 통계 저장, flow_stats[datapath_id][flow_id] = count<br>
&emsp;packet_count: IP별 총 패킷 수<br>
&emsp;byte_count: IP별 바이트 수<br>
&emsp;suspicious_ips: 공격 의심 IP 저장<br>
&emsp;connection_tracker: 각 IP가 보낸 timestamp 저장, deque 사용으로 오래된 요청 빠르게 제거<br>
&emsp;port_scan_tracker: src_ip에서 dst_ip 간에 접속한 포트들을 기록, 포트 스캔 판단 용도<br>
&emsp;DDOS_THRESHOLD, PORT_SCAN_THRESHOLD_TIME_WINDOW: 공격별 감지 기준 값 설정<br>
<br>

3. switch_features_handler()
```python
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATHCER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info('Switch connected: %s', datapath.id)

```
> NetworkController 클래스의 스위치 연결 시 이벤트 핸들러<br>

스위치가 처음 연결되면 실행되는 함수이다.<br>
datapath에 해당 스위치 객체를 받고, OpenFlow 프로토콜 인터페이스와 패킷 생성기를 ofproto, parser로 설정한다.<br><br>
OFPMatch()는 패킷에 룰을 적용하는 조건을 정의하는 객체로 스위치 flow table에 있는 각 룰은<br>
match 조건과 action을 포함한다.<br>
```python
match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_dst='10.0.0.1')
```
위 코드의 경우 들어온 포트가 1이고, IPv4 패킷이며 목적지 IP가 10.0.0.1인 경우에만 룰을 적용하라는 의미이다.<br>
code1.py에선 match = parser.OFPMatch()로 어떤 조건도 넣지 않았기에, 어떤 패킷이든 들어오면<br>
```python
actions = [parser.OFPActionOutput(ofproto.OFP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
```
스위치에서는 해당 패킷을 컨트롤러로 보내게된다. (최초에 컨트롤러가 모든 패킷을 처리)<br>
이후 해당 룰을 flow table에 설치하는 self.add_flow() 메소드를 불러와 인자로 match, actions를 넘겨준다.<br>
<br>

4. add_flow()
```python
def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
    ofproto = datapath.ofproto
    parser = ofproto.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
    datapath.send_msg(mod)
```
> 플로우 테이블에 플로우를 추가하는 메소드<br>

인자들은 각 다음과 같은 역할을 수행한다.<br>
-   datapath: flow를 설치할 스위치 객체
-   priority: flow의 우선 순위, 높을 수록 먼저 적용된다
-   match: 어떤 조건의 패킷에 flow를 적용할 지 정의하는 객체, OFPMatch()를 통해 생성한다
-   actions: match에 해당하는 패킷에 대해 어떠한 행동을 할 것인지
-   buffer_id: 특정 패킷을 처리하면서 flow를 설치할 경우, 해당 패킷의 ID
-   idle_timeout: flow가 사용되지 않은 시간이 값만큼 지나면 flow 삭제를 위한 인자
-   hard_timeout: flow 생성 후 해당 값만큼 시간이 지나면 무조건 삭제
<br>
ofproto, parser로 각각 OpenFlow 프로토콜과 파서를 가져온다.
```python
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
```
이후 actions를 instruction으로 감싸서 처리하는 OpenFlow 구조에 따라 inst를 생성한다.<br>
OFPIT_APPLY_ACTIONS는 actions를 바로 실행하라는 의미이며, actions는 2번에서 설명한 내용과 동일하다.<br>
따라서 위 코드는 add_flow과정에서 추가할 flow를 적용받는 패킷이 있을 경우 actions를 즉시 실행하게 한다.<br>

이어서 if buffer_id 조건문을 기준으로 FlowMod 메시지를 생성한다.<br>
OFPFlowMod는 스위치에 "이러한 flow를 flow table에 추가하라" 지시하는 메시지이며<br>
이때 buffer_id 2번에서 설명한 내용과 동일하다.<br>
마지막으로 생성한 mod를 스위치에 전송해서 flow를 설치한다. ```datapath.send_msg(mod)```<br>
<br>

5. block_ip()
```python
def block_ip(self, datapath, src_ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []
        self.add_flow(datapath, 1000, match, actions, hard_timeout=300)

        self.logger.warning("BLOCKED IP: $s for 5 minutes", src_ip)
```
> IP 차단 메소드<br>

ofproto와 parser는 앞선 메소드들의 기능과 동일하며<br>
eth_type=0x0800에 해당하는 IPv4 주소로부터 오는 모든 패킷을 DROP하는 match, actions를 생성한다.<br>
이후 5분의 유효 시간을 가지는 패킷 DROP flow를 스위치의 flow table에 추가한다.<br>
<br>

6. packet_in_handler()
```python
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def packet_in_handler(self, ev):
```
> 패킷 수신 시 처리를 담당하는 메소드<br>

스위치로부터 Packet-In 메시지가 도착했을 때 실행되며<br>
보통 스위치가 flow table에서 패킷을 처리하지 못하였을 때 발생한다.<br>
<br>

```python
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
```
ev.msg: 수신된 OpenFlow 메시지, 여기서는 Packet-In 메시지이다.<br>
datapath, ofproto: 앞서 설명한 내용과 일치<br>
parser: 메시지를 생성할 때 쓰인다. (OFPMatch, OFPFlowMod etc.)<br>
in_port: 스위치 입장에서 해당하는 패킷이 들어온 포트 번호<br>
pkt: 실제 패킷의 raw 데이터인 msg.data를 Ryu의 패킷 파서 객체 packet.Packet()으로 파싱한 패킷<br>
eth: Ethernet 프로토콜을 추출<br>
src, dst: Ethernet 헤더에서 source, destination MAC 주소<br>
dpid: 스위치의 고유 ID (Datapath ID)<br>

```python
self.mac_to_port.setdefault(dpid, {})
self.mac_to_port[dpid][src] = in_port
```
스위치 ID별로 MAC주소와 포트를 저장하는 딕셔너리인 mac_to_port에 dpid에 해당하는 value를 초기화하고<br>
src 맥주소에 해당하는 포트값인 in_port를 매핑한다. (Learning Switch 역할)<br>

```python
current_time = time.time()
self.analyze_traffic(pkt, current_time, datapath)
```
이후 현재 시간과 패킷 정보, 해당 스위치 객체 정보를 인자로 트래픽 분석 메소드를 실행한다.<br>

```python
if dst in self.mac_to_port[dpid]: out_port = self.mac_to_port[dpid][dst]
else: out_port = ofproto.OFPP_FLOOD

actions = [parser.OFPActionOutput(out_port)]
```
OFPP_FlOOD는 브로드캐스트처럼 모든 포트로 보내라는 의미이다. (들어온 포트는 제외)<br>
따라서 MAC주소->포트에 매핑한 mac_to_port[dpid]에 destination MAC주소가 있을 경우<br>
out_port에 해당 포트를 넣고, 없는 MAC주소일 경우 브로드캐스트한다.<br>
이 정보를 actions에 OFPActionOutput(outport)로 담는다.<br>

```python
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
```
이후에 out_port가 Flood가 아닌 mac_to_port에 매핑되어 있던 맥주소의 포트일 경우<br>
match를 OFPMatch()로 객체 생성한 후, 스위치의 flow table에 flow를 추가한다.<br>
해당 패킷을 스위치가 버퍼에 저장해둔 ID가 있을 경우 그것을 기준으로 처리하여 효율성을 높인다.<br>
<br>

7. analyze_traffic()
```python
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
``` 
> IPv4 패킷의 트래픽 분석 메소드<br>

ip_pkt으로 pkt.get_protocol(ipv4.ipv4)를 통해 패킷에서 IPv4 계층의 헤더를 추출한다.<br>
이때 Ethernet 프레임에 IPv4가 아닌 ARP, IPv6 등이 실려 있을 경우, None 반환으로 메소드를 종료한다.<br>

```python
src_ip = ip_pkt.src; dst_ip = ip_pkt.dst; protocol = ip_pkt.proto

self.packet_count[src_ip] += 1
self.connection_tracker[src_ip].append(current_time)

self.detect_ddos(src_ip, current_time, datapath)
```
패킷에서 source의 IP주소와, destination의 IP주소, 사용하는 프로토콜을<br>
src_ip, dst_ip, protocol 변수에 각각 할당한다.<br>
이후 송신자 측에 해당하는 src_ip의 packet_count 횟수를 추가하며, connection_tracker에서<br>
src_ip의 패킷 연결 시간을 최신화한다.<br>
current_time을 기반으로 src_ip의 DDOS 공격 여부를 판단하는 detect_ddos()함수를 실행한다.<br>
<br>

```python
if protocol == 6:
    tcp_pkt = pkt.get_protocol(tcp.tcp)
    if tcp_pkt: self.detect_port_scan(src_ip, dst_ip, tcp_pkt.dst_port, datapath)

if src_ip in self.suspicious_ips:
    self.logger.warning('Packet from suspicious IP %s to %s', src_ip, dst_ip)
```
protocol의 값이 6일 경우 TCP 통신에 해당하며,<br>
tcp_pkt 변수에 pkt.get_protocol(tcp.tcp)로 패킷에서 TCP 계층 헤더를 추출한다.<br>
TCP 헤더가 정상적으로 붙어 있는 지 확인하는 조건문 과정을 통해 실제 TCP 패킷인지 재확인하여<br>
헤더가 존재할 때 포트 스캔 감지 메소드를 호출한다.<br>
<br>
이후 src_ip가 공격자 의심 IP에 등록되어 있을 경우 경고 로그를 남긴다.<br>
<br>

8. detect_ddos()
```python
def detect_ddos(self, src_ip, current_time, datapath):
    connections = self.connection_tracker[src_ip]

    while connections and current_time - connections[0] > self.TIME_WINDOW: connections.popleft()
    
    if len(connections) > self.DDOS_THRESHOLD:
        if src_ip not in self.suspicious_ips:
            self.suspicious_ips.add(src_ip)
            self.logger.warning('DDOS DETECTED from IP: %s (Rate %d pkt/m)', src_ip, len(connections))
            self.block_ip(datapath, src_ip)
```
> DDoS 공격 탐지 메소드<br>

src_ip의 최근 접속 시각 타임 스탬프 deque을 connections 변수에 참조한다.<br>
이후 connections가 존재하고, 가장 오래된 접속 시각과 현재 시각의 차이가 TIME_WINDOW보다 클 경우 오랜 접속 기록을 제거한다.<br>
(while 반복을 통해, 오래된 항목 여러 항목을 모두 제거하여 준다)<br>
<br>
len()함수를 통해 남은 타임 스탬프의 개수를 세어, DDoS 공격 기준 문턱값보다 클 경우<br>
src_ip가 suspicious_ips에 들어있지 않다면 suspicious_ips에 IP를 추가한 후 DDoS 탐지 로그를 남긴다.<br>
이후 block_ip()함수로 실제 해당 IP의 차단 동작을 수행한다.<br>
<br>

9. detect_port_scan()
```python
def detect_port_scan(self, src_ip, dst_ip, dst_port, datapath):
    scan_key = f'{src_ip}->{dst_ip}'
    self.port_scan_tracker[scan_key].add(dst_port)

    unique_ports = len(self.port_scan_tracker[scan_key])

    if unique_ports > self.PORT_SCAN_THRESHOLD:
        if src_ip not in self.suspicious_ips:
            self.suspicious_ips.add(src_ip)
            self.logger.warning("PORT SCAN DETECTED from %s to %s (%d unique ports)", src_ip, dst_ip, unique_ports)

            self.block_ip(datapath, src_ip)
```
> 포트 스캔 공격 탐지 메소드<br>

포트 스캔 공격은 특정 대상에 대해 여러 포트를 순차적으로 시도하는 특징이 있어
src_ip와 dst_ip를 묶어 하나의 키, scan_key로 관리한다.
<br>
defaultdict(set)인 port_scan_tracker에 해당 scan_key에 대해 스캔 시도한 포트를 set(집합)에 추가한다.<br>
이후 공격자가 해당 목적지로 시도한 고유 포트 개수를 unique_ports에 계산한다.<br>

```python
if unique_ports > self.PORT_SCAN_THRESHOLD:
    if src_ip not in self.suspicious_ips:
        self.suspicious_ips.add(src_ip)
        self.logger.warning("PORT SCAN DETECTED from %s to %s (%d unique ports)", src_ip, dst_ip, unique_ports)

        self.block_ip(datapath, src_ip)
```
고유 포트 개수가 포트 스캔 공격 문턱값을 초과할 경우, 포트 스캔 공격이라 판단하여<br>
이미 suspicious_ips에 있는 지 확인 후 새로운 공격자 IP에 해당할 때<br>
suspicious_ips에 src_ip를 추가한 후, 포트 스캔 감지 로그를 출력하고 block_ip()과정으로 실제 차단 동작을 실행한다.<br>
<br>

10. get_traffic_stats()
```python
def get_traffic_stats(self):
    stats = {
        'total_packets': sum(self.packet_count.values()),
        'suspicious_ips': list(self.suspicious_ips),
        'top_talkers': sorted(self.packet_count.items(), key=lambda x: x[1], reverse=True)[:10]
    }
    return stats
```
> 수집한 네트워크 트래픽의 통계 정보 정리 반환 메소드<br>

stats 딕셔너리를 생성한 후 반환한다.<br>
total_packets: packet_count.values()로 꺼낸 각 패킷의 개수를 sum()한 총 패킷 수가 저장된다.<br>
suspicious_ips: suspicious_ips 집합을 list()로 변환하여 데이터가 저장된다. (순서가 있는 list 형식이 JSON 형태로 다루기 편리하여)<br>
top_talkers: packet_count에서 패킷의 개수에 따라 내림차순으로 정렬한다. 이후 상위 10개의 (IP, 패킷 개수) 쌍이 저장된다.<br>
<br>

11. reset_suspicious_ips()
```python
def reset_suspicious_ips(self):
    self.suspicious_ips.clear()
    self.logger.info("Suspicious IP list cleared")
```
> 공격자 의심 IP 목록 초기화 메소드<br>

공격자 의심 IP 딕셔너리 suspicious_ips의 요소를 clear()한 후, 해당 로그를 남긴다.<br>
<br>

12. others
```python
if __name__ == '__main__': pass
```
> 직접 실행 동작 거부 코드<br>

해당 컨트롤러 code1.py 코드는 모듈로써 class인 NetworkController의 기능 코드이기에<br>
직접 실행 시 어떠한 동작도 수행하지 않고 종료된다.<br>
