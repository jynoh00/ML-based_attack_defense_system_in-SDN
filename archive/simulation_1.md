# simulation-1
- simulator : /attack_simulator/code1.py
- controller: /ryu_controller/code1.py
- topology: /topology/topology_2/code2.py

# 의존성 패키지 설치
```bash
sudo apt update && sudo apt upgrade -y

sudo apt install mininet -y

sudo apt install python3-pip python3-dev -y

pip3 install ryu

pip3 install scapy

sudo apt install net-tools tcpdump wireshark -y
```

# 파일 권한 설정
```bash
chmod +x simulator

chmod +x controller

chmod +x topology
```

# Ryu 컨트롤러 실행, Mininet 네트워크 토폴로지 생성
```bash
ryu-manager controller --verbose

sudo python3 topology
```
controller: port 6653, OpenFlow 연결 대기<br>
topology:<br>
&emsp;클라이언트: client0(10.0.1.10), client1(10.0.1.11), client2(10.0.1.12)<br>
&emsp;서버: web_server(10.0.1.100), db_server(10.0.1.101), dns_server(10.0.1.102)<br>
&emsp;공격자: attacker0(10.0.1.200), attacker1(10.0.1.201)<br>
&emsp;모니터: monitor(10.0.1.250)

# 네트워크 연결 상태 확인 (Mininet CLI)
```bash
mininet> pingall

mininet> h1 ping -c 3 h2
```

# 공격 시뮬레이션 실행
```bash
sudo python3 simulator syn_flood 10.0.1.100

sudo python3 simulator udp_flood 10.0.1.100

sudo python3 simulator port_scan 10.0.1.100

sudo python3 simulator icmp_flood 10.0.1.100

sudo python3 simulator distributed 10.0.1.100

sudo python3 simulator normal 10.0.1.100
```
- SYN Flood attack: 30s, 100 pkts/s
- UDP Flood attack: 30s, 200 pkts/s
- Port Scan attack: port 1-1000 Scan 
- ICMP Flood attack: 20s
- Distributed attack: 5개 소스 동시 SYN Flood
- Normal: 60s, 정상 트래픽 생성

# 모니터링 및 분석
```bash
sudo tcpdump -i any -n host 10.0.1.100

sudo wireshark &
```
tcpdump -i any -n host 10.0.1.100: 특정 인터페이스 트래픽 캡처<br>
wireshark &: Wireshark로 패킷 분석 (GUI)

# Mininet 직접 테스트
```bash
mininet> attacker0 python3 simulator syn_flood 10.0.1.100 &

mininet> web_server netstat -an | grep :80

mininet> monitor tcpdump -i monitor-eth0 -n
```
- attacker0 호스트에서 직접 공격 실행
- web_server 연결 상태 확인
- monitor 호스트에서 트래픽 관찰

# 임계값 조정 및 시뮬레이션 종료
controller
```python
self.DDOST_THRESHOLD = 1000
self.PORT_SCAN_THRESHOLD = 10
self.TIME_WINDOW = 60
```
- DDOS 문턱값 (패킷/분)
- 포트 스캔 문턱값
- 시간 윈도우 (초)

```bash
mininet> exit

sudo mn -c
```
- Mininet 종료
- 네트워크 클리어
- Ctrl+C: 컨트롤러 종료
