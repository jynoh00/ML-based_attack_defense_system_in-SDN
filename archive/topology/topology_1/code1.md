# 관련 라이브러리 설치
```python
    from mininet.net import Mininet
    from mininet.cli import CLI
    from mininet.node import Host
    from mininet.node import OVSKernelSwitch
    from mininet.log import setLogLevel, info
    from mininet.node import RemoteController
    from mininet.term import makeTerm
```
<br>

# Mininet() 클래스, net 객체
```python
    def myTopo():
        net = Mininet(topo=None, autoSetMacs=False, build=False, ipBase='10.0.1.0/24')
```
Mininet에서 사용될 Topology를 정의하는 함수 `def myTopo()`
`Mininet()` 클래스로 `net` 네트워크 객체를 생성한다.<br>
topo 파라미터를 사용하여 Topology 객체를 전달하고
build 파라미터를 통해 Topology 객체를 빌드할 지 여부를 정할 수 있다.<br>
autoSetMacs 파라미터를 통해 MAC 주소를 IP 주소와 같이 자동으로 설정할 지 정할 수 있으며
ipBase 파라미터는 호스트들의 기본 IP 주소를 설정하는 데 사용된다.<br>

# net.addHost() || addSwitch()
```python
    h1 = net.addHost('client', cls=Host, defaultRoute=None)
    h2 = net.addHost('server1', cls=Host, defaultRoute=None)
    h3 = net.addHost('server2', cls=Host, defaultRoute=None)

    c1 = net.addController('c1', RemoteController)
    s1 = net.addSwitch('s1', protocols='OpenFlow13', failMode='standalone')
```
Mininet에서 호스트와 스위치를 설정
`addHost()` 함수를 사용하여 호스트를 설정할 수 있으며
호스트의 이름, 클래스 및 생성자 등의 파라미터를 받아 호스트를 생성한다.<br>
스위치는 `addSwitch()`함수를 사용하여 설정하며
스위치의 이름, 클래스, 실패 모드 등의 파라미터를 받아 스위치를 생성한다.<br><br>

```python
addHost(name=이름, cls=클래스 혹은 constructor제작(custom), defaultRoute=None)
addSwitch(name=이름, cls=클래스 혹은 constructor, failMode='standalone' or 'secure')
```
위와 같은 형식으로 호스트와 스위치를 설정한다.<br><br>

# net.addLink()
```python
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
```
Mininet에서 호스트와 스위치를 설정한 후, addLink() 함수를 사용하여 연결시킨다.<br>
(스위치는 Link 계층의 네트워크 장비이다)<br><br>

addLink()함수는 두 개의 매개변수(호스트/스위치 객체)를 받아서 Link를 만들어준다.<br>
위 예시는 s1 스위치에 3개의 호스트를 Link 설정으로 연결한 것이다.<br>

# setIP(intf=, ip=)
```python
    h1.setIP(intf='client-eth0', ip='10.0.1.5/24')
    h2.setIP(intf='server1-eth0', ip='10.0.1.2/24')
    h3.setIP(iintf='server2-eth0', ip='10.0.1.3/24')
```
Mininet에서 addHost()함수를 사용하여 호스트를 설정한 후 호스트의 인터페이스(eth0)와 IP주소를 설정한다.<br>

# net.build(), net.start(), CLI(), net.stop()
```python
    net.build()
    net.start()

    CLI()
    net.stop()
```
net.build() 함수를 사용하여 네트워크를 구축하며 net.start()함수를 사용하여 네트워크를 시작한다.<br><br>

CLI()함수는 Mininet에서 가상 네트워크를 제어하고 관리하기 위한 인터페이스를 제공한다.<br>
해당 함수를 호출할 경우 Mininet CLI(Command Line Interface)를 실행할 수 있으며<br>
이 CLI를 통해 가상 네트워크를 관리하고, 각 노드 간의 통신을 테스트할 수 있다.<br><br>

h2에서 h3로 ping 명령을 보내고자 할 경우, CLI 명령어 창에서 다음과 같이 입력한다.
`mininet> h2 ping h3`
<br>

# if __name__ == '__main__':
```python
if __name__ == '__main__':
    setLogLevel('info')
    myTopo()
```
main() 함수에서 myTopo()함수를 호출한다.<br>
myTopo() 함수는 앞서 정의한 가상 네트워크 구성 정보를 포함하고 있는 Topology 객체를 반환하며<br>
반환한 객체를 Mininet 클래스의 인스턴스를 생성할 때 인자로 전달하여 가상 네트워크를 생성하고 실행한다.<br><br>

setLogLevel('info') 함수는 Mininet의 로그 레벨을 설정하는데<br>
'info' 레벨은 로그를 상세히 출력하는 레벨 중 하나로 다음과 같은 로그 레벨을 지원한다.<br>
1. debug: 가장 상세한 로그 레벨, 디버깅용으로 사용
2. info: 일반적인 정보를 제공하는 로그 레벨
3. output: 출력 결과를 로그로 기록
4. warning: 경고 메시지를 로그로 기록
5. error: 오류 메시지를 로그로 기록

# output
결과적으로 cod1.py를 리눅스 기반 운영체제에서 실행 시<br>
Mininet CLI가 활성화되며 네트워크 명령을 통해 네트워크를 제어하고 테스트할 수 있다.<br><br>

# others
```python
    #!/usr/bin/python
```
셔뱅(Shebang), 스크립트 실행 시 사용할 Python 인터프리터 경로 지정
<br>

```python
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm
```
각 라이브러리 별 역할 및 기능<br>
Mininet: Mininet의 핵심 클래스 임포트, 전체 네트워크 토폴로지를 생성하고 관리하는 메인 클래스<br>
CLI: Command Line interface 클래스 임포트, 사용자가 네트워크와 상호작용할 수 있는 대화 환경 제공<br>
Host: 가상 호스트 노드 클래스 임포트, 네트워크 상 엔드포인트(클라이언트, 서버) 역할<br>
OVSKernelSwitch: OpenvSwitch 커널 모드 스위치 클래스 임포트, OpenFlow 프로토콜을 지원하는 가상 스위치<br>
로깅 관련 함수 임포트<br>
    setLogLevel: 로그 출력 레벨 설정<br>
    info: 정보 메시지 출력<br>
RemoteController: 원격 컨트롤러 클래스 임포트, 외부 SDN 컨트롤러와 연결하여 중앙집중식 네트워크 제어<br>
makeTerm: 터미널 생성 함수 임포트, 각 노드별로 독립적인 터미널 창을 생성<br>
<br><br>
```python
    c1 = net.addController('c1', RemoteController)
```
c1 원격 컨트롤러 추가, RemoteControlloer: 외부 SDN 컨트롤러 사용 (기본적으로 localhost:6633)<br><br>

```python
    net.build()
    net.start()
```
net.build()는 추가한 모든 노드들로 실제 네트워크를 구축하는 과정 (가상 인터페이스 생성 및 초기화)<br>
net.start()는 구성된 네트워크를 실제로 시작, 모든 노드와 링크가 활성화된다.<br><br>

```python
    net.terms += makeTerm(c1)
    net.terms += makeTerm(h1)
    net.terms += makeTerm(h2)
    net.terms += makeTerm(h3)
```
컨트롤러 c1, 3개의 호스트에 대한 독립적인 터미널 창 생성 (GUI 환경에서 별도 터미널로 표시)<br><br>


# 주요 구조 및 의존성
주요 구조
1. Library Import: Mininet 핵심 모듈
2. Network 생성: Host 3개 + Switch 1개 + 컨트롤러 1개
3. Topology: Star 구조 (모든 호스트가 중앙 스위치에 연결)
4. 수동 MAC/IP 주소 할당
5. CLI를 통한 대화형 네트워크 제어<br><br>

주요 의존성
1. OpenvSwitch 가상 스위치
2. Python
3. Linux Network Namespace
4. iptables: 방화벽 및 NAT 기능
