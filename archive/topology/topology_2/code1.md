# 주요 사항 (0805/code1.py -> 0806/code1.py)

0. main terminal output
```
noh@ubuntu-noh:~/Desktop/sdn_code/code1$ sudo python3 myTopo.py
[sudo] password for noh:
Unable to contact the remote controller at 127.0.0.1:6653
Unable to contact the remote controller at 127.0.0.1:6633
Setting remote controller to 127.0.0.1:6653
*** Configuring hosts
client *** defaultIntf: warning: client has no interfaces
server1 *** defaultIntf: warning: server1 has no interfaces
server2 *** defaultIntf: warning: server2 has no interfaces

*** Starting controller
c1
*** Starting 1 switches
s1 ...
*** Starting CLI:
```

1. Unable to contact the remote controller
```
Unable to contact the remote controller at 127.0.0.1:6653
Unable to contact the remote controller at 127.0.0.1:6633
Setting remote controller to 127.0.0.1:6653
```
<br>
정상적으로 코드가 실행되었으나 Unable 메시지가 발생

```
Unable to contact the remote controller at 127.0.0.1:6653
Unable to contact the remote controller at 127.0.0.1:6633
Setting remote controller to 127.0.0.1:6653
```
RemoteController로 설정된 c1이 OpenFlow 컨트롤러에 연결을 시도하였으나 (6653, 6633 포트)<br>
해당 포트에서 동작 중이던 컨트롤러를 찾지 못하였음<br>
Setting remote controller to 127.0.0.1:6653, 6653 포트에 기본적으로 연결 시도는 계속 유지<br>
이후, 컨트롤러가 127.0.0.1:6653 포트에 뜰 경우 자동으로 연결됨<br>

<br>

2. warning: has no interfaces
```
client *** defaultIntf: warning: client has no interfaces
server1 *** defaultIntf: warning: server1 has no interfaces
server2 *** defaultIntf: warning: server2 has no interfaces
```

<br>
net.build()가 링크 이전에 호출되었기에, Host 객체가 인터페이스를 자동으로 못 잡아 발생<br>
net.build()를 addLink()를 통한 모든 링크 설정 이후에 함수 호출하여 해결<br>
<br>
net.build()는 Mininet 내부에서 각 노드(호스트, 스위치, 컨트롤러)의 내부 설정을 초기화하는 단계로<br>
setIP(), setMAC()과 같은 메서드는 각 호스트가 가지고 있는 인터페이스가 준비된 이후에 호출되어야 한다.<br>
이떄 인터페이스가 생성되는 시점은 addLink() 이후이다.<br>

```python
net.addHost(...)      # 호스트 추가
net.addSwitch(...)    # 스위치 추가
net.addLink(...)      # 링크 연결 (인터페이스 생성됨)
net.build()           # 내부 네트워크 구성 초기화 (컨트롤러 제외)
setIP(), setMAC()     # 인터페이스에 IP, MAC 할당
net.start()           # 컨트롤러 및 스위치 시작
```
<br>

3. sudo apt install xterm
```python
net.terms += makeTerm(c1); net.terms += makeTerm(h1)
net.terms += makeTerm(h2); net.terms += makeTerm(h3)
```
makeTerm()을 통해, 개별 터미널을 실행하게 작성하였는데 추가 터미널 창이 열리지 않는 문제 발생<br>
Mininet에서 makeTerm()은 각 노드의 xterm 터미널을 띄우는 코드이다. 따라서 xterm 패키지를 추가로 설치하여야한다.<br>

```
sudo apt update
sudo apt install xterm
```

