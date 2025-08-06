# Enhanced Mininet Topology Code Explain (code2.py)
#### 20203009 JY_NOH

1. Library Import
```python
    from mininet.net import Mininet
    from mininet.cli import CLI
    from mininet.node import Host
    from mininet.node import OVSKernelSwitch
    from mininet.log import setLogLevel, info
    from mininet.node import RemoteController
    from mininet.term import makeTerm
    from mininet.link import TCLink
    import time
```
> TCLink, time 라이브러리 추가<br>
&emsp;TCLink: Link 속성(bw, delay, loss etc.)을 설정할 수 있는 링크 객체<br>
&emsp;time: 대기(sleep) 기능을 위한 표준 라이브러리<br>
<br>

2. Controller, Switches
```python
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653, protocols='OpenFlow13')
    s0 = net.addSwitch('s0', protocols='OpenFlow13')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
```
> 원격 컨트롤러 controller 1개와 3개의 스위치 추가<br>
&emsp;controller: OpenFlow1.3 프로토콜, 포트 6653 사용<br>
&emsp;s0, s1, s2: 맥 주소 기반 패킷 전달을 위한 링크 계층 L2 스위치<br>
<br>

3. Hosts
```python
    client0 = net.addHost('client0', cls=Host, ip='10.0.1.10/24', defaultRoute=None)
    client1 = net.addHost('client1', cls=Host, ip='10.0.1.11/24', defaultRoute=None)
    client2 = net.addHost('client2', cls=Host, ip='10.0.1.12/24', defaultRoute=None)

    web_server = net.addHost('web_server', cls=Host, ip='10.0.1.100/24', defaultRoute=None)
    db_server = net.addHost('db_server', cls=Host, ip='10.0.1.101/24', defaultRoute=None)
    dns_server = net.addHost('dns_server', cls=Host, ip='10.0.1.102/24', defaultRoute=None)

    attacker0 = net.addHost('attacker0', cls=Host, ip='10.0.1.200/24', defaultRoute=None)
    attacker1 = net.addHost('attacker1', cls=Host, ip='10.0.1.201/24', defaultRoute=None)

    monitor = net.addHost('monitor', cls=Host, ip='10.0.1.250/24', defaultRoute=None)
```
> 네트워크 내 호스트 생성부<br>
&emsp;client0-2: 클라이언트 호스트<br>
&emsp;web, db, dns_server: 서버 호스트<br>
&emsp;attacker0-1: 공격자 호스트<br>
&emsp;monitor: 총괄 모니터링 호스트<br>
<br>

4. Creating links
```python
    net.addLink(s0, s1, bw=100); net.addLink(s0, s2, bw=100)
    net.addLink(client0, s1, bw=10); net.addLink(client1, s1, bw=10); net.addLink(client2, s1, bw=10)
    net.addLink(web_server, s2, bw=50); net.addLink(db_server, s2, bw=50); net.addLink(dns_server, s2, bw=20)
    net.addLink(attacker0, s0, bw=20); net.addLink(attacker1, s0, bw=20)
    net.addLink(monitor, s0, bw=100)
```
> 스위치 및 각 호스트 간 링크 생성부<br>
&emsp;100Mbps 대역폭 사용, s0가 s1, s2와 링크되어 중앙 core 역할<br>
&emsp;10Mbps 대역폭 사용, s1에 client0-2의 호스트가 링크<br>
&emsp;50, 20Mbps 대역폭 사용, s2에 web-db-dns_server 링크<br>
&emsp;20Mbps 대역폭으로, attacker0-1 s0 링크<br>
<br>

5. MAC address setting
```python
    client0.setMAC(intf='client0-eth0', mac='00:00:00:00:01:10')
    client1.setMAC(intf='client1-eth0', mac='00:00:00:00:01:11')
    client2.setMAC(intf='client2-eth0', mac='00:00:00:00:01:12')

    web_server.setMAC(intf='web_server-eth0', mac='00:00:00:00:01:00')
    db_server.setMAC(intf='db_server-eth0', mac='00:00:00:00:01:01')
    dns_server.setMAC(intf='dns_server-eth0', mac='00:00:00:00:01:02')

    attacker0.setMAC(intf='attacker0-eth0', mac='00:00:00:00:02:00')
    attacker1.setMAC(intf='attacker1-eth0', mac='00:00:00:00:02:01')

    monitor.setMAC(intf='monitor-eth0', mac='00:00:00:00:00:01')
```
> 각 구성요소의 MAC 주소 수동 설정 및 인터페이스명 설정부<br>
<br>

6. xterm GUI
```python
    net.terms += makeTerm(monitor, title="Monitor", term="xterm")
    net.terms += makeTerm(attacker0, title="Attacker0", term="xterm")
    net.terms += makeTerm(web_server, title="WebServer", term="xterm")
```
> 주요 호스트들의 GUI 터미널 xterm 생성부<br>
<br>

7. server services setup
```python
    web_server = net.get('web_server')
    web_server.cmd('echo "Hello from Web Server" > /tmp/index.html')
    web_server.cmd('cd /tmp && python3 -m http.server 80 &')

    dns_server = net.get('dns_server')
    dns_server.cmd('echo "nameserver 8.8.8.8" > /etc/resolv.conf')

    db_server = net.get('db_server')
    db_server.cmd('nc -l -p 3306 &')
``` 
> basic server services<br>
web_server: /tmp/index.html 파일 생성 후, 포트 80으로 http 서버 실행<br>
dns_server: /etc/resolv.conf 파일에 외부 DNS 서버(Google DNS) 명시, DNS 기능 적용<br>
db_server: netcat(nc)을 사용해 포트 3306(MySQL)을 열어 단순 대기 상태로 설정<br>
<br>

8. run_simul(net)
```python
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
```
> 시뮬레이션 테스트 함수, 간단한 연결 및 서비스 테스트 실행<br>
client0에서 web_server로 ping을 보낸 후, 결과값 res를 통해 성공 여부 판단<br>
이후 client0에서 web_server로 HTTP 요청, 결과값 res를 통해 성공 여부 판단<br>
<br>

9. main()
```python
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
```
> 메인 함수부<br>
&emsp;로그 출력 레벨을 info로 설정, net 변수로 네트워크 객체를 생성<br>
&emsp;time 라이브러리를 통해 컨트롤러 준비 시간을 확보한 후 시뮬레이션 시작<br>
&emsp;net 네트워크를 인자로, Mininet CLI 인터페이스를 실행<br>
&emsp;키보드 인터럽 및 종료 설정<br>
<br>

