# ML-based SDN Attack Defense System in SDN

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-16+-green.svg)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-4.x-lightgrey.svg)](https://expressjs.com/)
[![HTML5](https://img.shields.io/badge/HTML5-orange.svg)](https://developer.mozilla.org/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-blue.svg)](https://developer.mozilla.org/docs/Web/CSS)
[![JavaScript](https://img.shields.io/badge/JavaScript-yellow.svg)](https://developer.mozilla.org/docs/Web/JavaScript)
[![C++](https://img.shields.io/badge/C++-17-red.svg)](https://isocpp.org/)
[![libpcap](https://img.shields.io/badge/libpcap-1.10-lightblue.svg)](https://www.tcpdump.org/)
[![chrono](https://img.shields.io/badge/chrono-C++17-brightgreen.svg)](https://en.cppreference.com/w/cpp/chrono)
[![mutex](https://img.shields.io/badge/mutex-C++17-purple.svg)](https://en.cppreference.com/w/cpp/thread/mutex)
[![thread](https://img.shields.io/badge/thread-C++17-blueviolet.svg)](https://en.cppreference.com/w/cpp/thread)
[![atomic](https://img.shields.io/badge/atomic-C++17-darkgreen.svg)](https://en.cppreference.com/w/cpp/atomic)
[![memory](https://img.shields.io/badge/memory-C++17-lightgreen.svg)](https://en.cppreference.com/w/cpp/memory)
[![iomanip](https://img.shields.io/badge/iomanip-C++17-orange.svg)](https://en.cppreference.com/w/cpp/io/manip)
[![Mininet](https://img.shields.io/badge/Mininet-2.3.0-brightgreen.svg)](http://mininet.org/)
[![Ryu](https://img.shields.io/badge/Ryu-SDN-orange.svg)](https://osrg.github.io/ryu/)

> **머신러닝 기반의 SDN 네트워크 공격 방어 시스템**  
> Software Defined Networking 환경에서 실시간 위협 탐지 및 자동화된 보안 대응을 제공하는 시스템 개발

## 목차

- [프로젝트 개요](#프로젝트-개요)
- [시스템 아키텍처](#시스템-아키텍처)
- [핵심 기능](#핵심-기능)
- [기술 스택](#기술-스택)

## 프로젝트 개요

소프트웨어 정의 네트워크(SDN: Software Defined Networking) 환경에서 발생할 수 있는 다양한 보안 위협에 대응하기 위한 머신러닝 기반의 자동화된 공격 탐지 및 방어 시스템을 설계하고 구현 및 최적화함을 목표로 한다. 머신러닝 알고리즘을 활용하여 SDN 네트워크에서 발생하는 다양한 공격을 실시간으로 탐지하고 자동으로 대응하는 지능형 보안 시스템을 구현한다.

### 해결하고자 하는 문제

- **DDoS Attack**: 대용량 트래픽을 통한 서비스 거부 공격
- **Flow Table Overflow**: 플로우 테이블 포화 공격
- **Controller Hijacking**: 컨트롤러 탈취 시도
- **Topology Poisoning**: 네트워크 토폴로지 조작
- **Man-in-the-Middle**: 중간자 공격
- etc.

## 시스템 아키텍처

```mermaid
graph TB
    A[웹 대시보드<br/>Node.js + Express] --> B[Python ML Engine]
    B --> C[Ryu SDN Controller]
    C --> D[Mininet Virtual Network]
    E[C++ Packet Analyzer] --> B
    F[실시간 트래픽] --> E
    
    subgraph "머신러닝 모듈"
        B1[위협 탐지 모델]
        B2[트래픽 분석 엔진]
        B3[이상 행위 탐지]
    end
    
    B --> B1
    B --> B2  
    B --> B3
```

## 핵심 기능

### 지능형 위협 탐지
- **실시간 ML 기반 공격 탐지**: Random Forest, SVM, Neural Network 앙상블 모델
- **이상 탐지**: LSTM 기반 시계열 분석으로 비정상 트래픽 패턴 식별
- **적응형 학습**: 새로운 공격 패턴에 대한 온라인 학습

### 자동화된 방어 시스템
- **Dynamic Flow Rule Management**: 공격 트래픽 자동 차단
- **Traffic Shaping**: QoS 기반 트래픽 제어
- **Topology Reconfiguration**: 공격 경로 우회를 위한 동적 라우팅

### 실시간 모니터링 & 시각화
- **실시간 대시보드**: 네트워크 상태 및 위협 현황 모니터링
- **3D 네트워크 토폴로지**: 인터랙티브 네트워크 구조 시각화
- **공격-방어 시나리오**: 실시간 공격 탐지 및 대응 과정 애니메이션

## 기술 스택

### Python (ML Engine & SDN Controller)
```python
# 주요 라이브러리
- TensorFlow / PyTorch  # 딥러닝 모델
- Scikit-learn          # 전통적 ML 알고리즘  
- Ryu Framework         # SDN 컨트롤러
- Mininet              # 네트워크 가상화
- Pandas, NumPy        # 데이터 처리
- Scapy               # 패킷 분석
- subprocess
- threading
- socket
- Ryu
- 
```

### Node.js (Web Dashboard)
```javascript
// 주요 기술 스택
- Express.js          // 웹 서버
- Socket.io          // 실시간 통신
- D3.js             // 데이터 시각화
- Three.js          // 3D 네트워크 토폴로지
- Chart.js          // 차트 및 그래프
- Bootstrap        // UI 프레임워크
- cookie-parser
- body-parser
- debug
- ejs
- morgan
```

### C++ (High-Performance Packet Processing)
```cpp
// 핵심 모듈
- libpcap           // 패킷 캡처
- Boost Libraries   // 네트워크 프로그래밍
- OpenMP           // 병렬 처리
- Protocol Buffers // 데이터 직렬화
- dpdk            // 고속 패킷 처리 (옵션)
- memory
- chrono
- netinet/ip, tcp, if_ether.h
- arpa/inet.h
- iomanip
```

## 웹사이트 미리보기

가상 네트워크 환경에서의 공격-방어 과정 패킷 분석 및 처리 과정을 json 통신 및 socket을 통해
web UI로 직관적으로 살펴보고 테스트를 제어할 수 있으며, http 공격을 해당 웹페이지로 하여 방어 성공 유무에 따른 결과를 바로 볼 수 있는 사이트
(추후 추가 업데이트)
---

### 화면 미리보기

#### 메인 페이지 및 프로젝트 소개
![화면 1](images/screens/img1.png)  
*화면 1: 홈페이지 메인 부*

![화면 2](images/screens/img2.png)  
*화면 2: 프로젝트 소개 부*

---

#### 배경지식
| 화면 3 | 화면 4 |
|--------|--------|
| ![화면 3](images/screens/img3.png) | ![화면 4](images/screens/img4.png) |
| *화면 3: 배경지식 부* | *화면 4: 상세 페이지 로드* |

### 시스템 설계 및 구현
| 화면 5 | 화면 6 |
|--------|--------|
| ![화면 5](images/screens/img5.png) | ![화면 6](images/screens/img6.png) |
| *화면 5: 시스템 설계 및 구현 부* | *화면 6: 상세 페이지 로드* |

#### 시뮬레이션
| 화면 7 | 화면 8 |
|--------|--------|
| ![화면 7](images/screens/img7.png) | ![화면 8](images/screens/img8.png) |
| *화면 7: 시뮬레이션 부* | *화면 8: 상세 페이지 로드* |

---

#### 참고문헌 및 프로필
![화면 9](images/screens/img9.png)  
*화면 9: 참고문헌 부*

![화면 10](images/screens/img10.png)  
*화면 10: 프로필 부*

