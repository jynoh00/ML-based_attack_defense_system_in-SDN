# README.md

# ML-based SDN Network Defense System

## 프로젝트 개요

본 프로젝트는 **CIC-IDS 2017**과 **NSL-KDD** 데이터셋을 활용하여 머신러닝(ML: Machine Learning) 기반의 SDN(Software Defined Network) 네트워크에서 공격 탐지 및 방어하는 시스템을 구현한다.

### 주요 특징
- **실시간 공격 탐지**: ML 모델을 통한 DDoS, 포트 스캔, 무차별 공격 등 탐지
- **자동 대응**: 공격 탐지 시 동적 플로우 규칙 설치 및 IP 차단
- **다양한 ML 학습 모델**: Random Forest, SVM, Neural Network, Ensemble
- **종합 모니터링**: 실시간 네트워크 시각화 및 성능 추적
- **공격 시뮬레이션**: 다양한 공격 패던 테스트 지원

## 단계별 실행 방법

### 1. 환경 설정

```bash
# 1. 의존성 설치 (사용 OS: Ubuntu 24.04.2 LTS)
sudo apt-get update
sudo apt-get install python3-pip python3-dev build-essential
sudo apt-get intsall mininet openvswitch-switch
sudo apt-get install tcpdump wireshark-common

# 2. 디렉토리 생성
mkdir ml_sdn_defense_system
cd ml_sdn_defense_system

# 3. Python 가상환경
python3 -m venv venv
source venv/bin/activate

# 4. 패키지 설치
pip install -r requirements.txt
```

### 2. 프로젝트 구조

```
ml_sdn_defense_system/
├── data/
│   ├── datasets/           
│   ├── processed/          
│   └── models/             
├── src/
│   ├── ml_models/
│   │   ├── data_preprocessing.py
│   │   ├── feature_extraction.py
│   │   ├── ml_trainer.py
│   │   └── model_evaluator.py
│   ├── sdn/
│   │   ├── ml_defense_controller.py
│   │   └── topology_manager.py
│   ├── network/
│   │   ├── advanced_topology.py
│   │   ├── traffic_generator.py
│   │   └── attack_simulator_enhanced.py
│   ├── monitoring/
│   │   ├── real_time_monitor.py
│   │   ├── packet_analyzer.py
│   │   └── alert_manager.py
│   └── utils/
│       ├── config.py
│       ├── logger.py
│       └── visualization.py
├── config/
│   └── config.yaml
├── logs/
├── tests/
├── requirements.txt
├── setup.py
└── README.md
```

```bash
# 디렉토리 구조 생성
mkdir -p {data/{datasets,processed,models},src/{ml_models,sdn,network,monitoring,utils},logs,config,tests}
```

### 3. 데이터 준비, 전처리

```bash
# 1. 데이터셋 다운로드 + 전처리
python src/ml_models/data_preprocessing.py --dataset both --download

# 2. CIC-IDS 2017 데이터셋 (수동 다운로드)
# https://www.unb.ca/cic/datasets/ids-2017.html
# data/datasets/cicids2017/ 디렉토리에 CSV 파일들 삽입

python src/ml_models/data_preprocessing.py --dataset cicids2017 --sample-size 100000

# 3. NSL-KDD 데이터셋 (자동 다운로드)
python src/ml_models/data_preprocessing.py --dataset nslkdd --sample-size 50000

# 4. Feature 추출
python3 src/ml_models/feature_extraction.py --input data/processed/cicids2017/X_train.csv --output data/processed/cicids2017_features/
```

### 4. ML 모델 훈련

```bash
# 1. CIC-IDS 2017 데이터셋 전체 훈련
python src/ml_models/ml_trainer.py --dataset cicids2017 --data-path data/processed/cicids2017/ --models all

# 2. 특정 모델 훈련 (하이퍼파라미터 튜닝)
python src/ml_models/ml_trainer.py --dataset cicids2017 --data-path data/processed/cicids2017/ --models random_forest --hyperparameter-tuning

# 3. NSL-KDD 데이터셋 훈련
python src/ml_models/ml_trainer.py --dataset nslkdd --data-path data/processed/nslkdd/ --models ensemble

# 4. 딥러닝 모델 훈련
python src/ml_models/ml_trainer.py --dataset cicids2017 --data-path data/processed/cicids2017/ --models deep_neural_network
```

### 5. SDN 컨트롤러 실행

```bash
# terminal 1 (Ryu 컨트롤러 실행)
ryu-manager src/sdn/ml_defense_controller.py --verbose
```

### 6. 네트워크 토폴로지 생성

```bash
# terminal 2 (네트워크 토폴로지 실행)
sudo python src/network/advanced_topology.py --topology enterprise --controller-ip 127.0.0.1 

# (테스트 용 심플 토폴로지)
sudo python src/network/advanced_topology.py --topology simple --controller-ip 127.0.0.1
```

### 7. 실시간 모니터 실행

```bash
# terminal 3 (GUI 모니터링 시스템)
python src/monitoring/real_time_monitor.py --controller-ip 127.0.0.1 --controller-port 8080

# (헤드리스 모드)
python src/monitoring/real_time_monitor.py --controller-ip 127.0.0.1 --headless
```

### 8. 공격 시뮬레이션 실행

```bash
# terminal 4 (공격 시뮬)

# 1. SYN Flood
sudo python src/network/attack_simulator_enhanced.py --target 10.0.1.100 --attack syn_flood --duration 60 --rate 1000

# 2. Port Scan
sudo python src/network/attack_simulator_enhanced.py --target 10.0.1.100 --attack port_scan --stealth

# 3. HTTP Flood
sudo python src/network/attack_simulator_enhanced.py --target 10.0.1.100 --attack http_flood --duration 120 --rate 500

# 4. Mixed attack
sudo python src/network/attack_simulator_enhanced.py --target 10.0.1.100 --attack mixed --duration 300

# 5. 봇넷 시뮬
sudo python src/network/attack_simulator_enhanced.py --target 10.0.1.100 --attack botnet --duration 180

# 6. 정상 트래픽
sudo python src/neywork/attack_simulator_enhanced.py --target 10.0.1.100 --attack normal --duration 300 --rate 10
```

### 9. 결과 확인 및 분석
```bash
# 1. 로그 파일
tail -f logs/ml_defense.log | grep "THREAT DETECTED"
tail -f logs/network_monitor.log
tail -f logs/attack_simulator.log

# 2. 통계
cat logs/performance_stats.json | jq .
cat logs/attack_stats.json | jq .

# 3. 알림 로그
cat logs/alerts.json | jq .

# 4. 모델 성능 결과
ls data/models/*/results.json
cat data/models/cicids2017_random_forest_*/results.json | jq.metrics
```

## 실행 중 확인사항

### 컨트롤러 상태
```bash
# OpenFlow 연결 확인
sudo netstat -tlnp | grep 6653

# 스위치 상태 확인
sudo ovs-vsctl show
```

### 네트워크 연결
```bash
# Mininet CLI
mininet> pingall
mininet> iperf h1 h2
mininet> dump
```

### 공격 탐지
```bash
# 실시간 공격 탐지 로그 출력
tail -f logs/ml_defense.log | grep -E '(THREAT|BLOCKED|SUSPICIOUS)'
```

## 성능 측정 및 평가

### ML 모델 성능
```python
# Python 스크립트
import json
import pandas as pd

with open('data/models/cicids2017_comparison.csv', 'r') as f: comparison = pd.read_csv(f)

print(comparison)

# 최고 성능 모델
best_model = comparison.loc[comparison['F1-Score'].idxmax()]
print(f'Best Model: {best_model['Model']}')
print(f'F1-Score: {best_model['F1-Score']:.4f}')
```

### 네트워크 처리량
```bash
# Mininet 대역폭 테스트
mininet> iperf h1 h2

# 공격 시나리오 처리량
mininet> h1 iperf -s &
mininet> h2 iperf -c 10.0.1.10 -t 60
```

### 응답 시간 측정
```bash
# 평균 응답 시간
grep 'prediction_time_avg' logs/performance_stats.json

# 탐지까지 걸린 시간
grep 'THREAT DETECTED' logs/ml_defense.log | head -10
```

## 문제 발생 시

### 일반적 오류

**Permission Denied(Raw Socket)**
```bash
# sudo 실행
sudo python src/network/attack_simulator_enhanced.py

# 권한 설정
sudo setcap cap_net_raw+ep $(which python3)
```

**Controller Connection Failed**
```bash
# Ryu 컨트롤러 재시작
pkill ryu-manager
ryu-manager src/sdn/ml_defense_controller.py --verbose

# OVS 재시작
sudo service openvswitch-switch restart
```

**Mininet 네트워크 정리**
```bash
# 기존 미니넷 정리
sudo mn -c
sudo killall -9 python3

# OVS 브리지 정리
sudo ovs-vsctl del-br s1 s2 s3
```

**ML 모델 로딩 오류**
```bash
# 모델 파일 확인
ls -la data/models/

# 모델 호환성 확인
python -c 'import joblib; print(joblib.__version__)'
python -c 'import sklearn; print(sklearn.__versin__)'
```

### 디버그 모드
```bash
# 상세 로그 활성화
export ML_SDN_LOG_LEVEL='DEBUG'

# 컨트롤러 디버그 모드
ryu-manager src/sdn/ml_defense_controller.py --verbose --log-level DEBUG

# 모니터링 디버그 모드
python src/monitoring/real_time_monitor.py --log-level DEBUG
```

## 결과

### 정상 실행 시 기대값
- **탐지 정확도**: 95% <= value
- **False Positive Rate**: 5% > value
- **응답 시간**: 100ms > value
- **처리량**: 초당 1000+ flow 처리

### 실제 실행 결과
- **탐지 정확도**:
- **False Positive Rate**:
- **응답 시간**:
- **처리량**:

## 추가 실험 및 확장

### 커스텀 공격 패턴
```python
# 사용자 정의 공격
class CustomAttackSimulator(EnhancedAttackSimulator):
    def slow_ddos_attack(self, duration=300, rate=50):
        # 저속 지속 공격 구현 부
        pass
```

### 신규 feature 추가
```python
def extracct_advanced_features(packet_data):
    # 고급 feature 추출 로직 구현 부
    pass
```

### 성능 최적화
```bash
# 멀티프로세싱 활성화
export ML_SDN_MULTIPROCESSING=true

# GPU 가속 활성화 (TensorFlow)
export CUDA_VISIBLE_DEVICES=0
```
