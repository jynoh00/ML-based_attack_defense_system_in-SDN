let simulationActive = false;
let attackCounter = 0;
let blockedIPs = 0;
let currentTraffic = 0;

function addLog(message, type = 'info') {
    const log = document.getElementById('log');
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

function updateStats() {
    document.getElementById('traffic-volume').textContent = currentTraffic;
    document.getElementById('attack-detected').textContent = attackCounter;
    document.getElementById('blocked-ips').textContent = blockedIPs;
    document.getElementById('response-time').textContent = Math.floor(Math.random() * 50 + 10);
}

function setNodeStatus(nodeId, status) {
    const node = document.getElementById(nodeId);
    const indicator = node.querySelector('.status-indicator');
    indicator.className = `status-indicator status-${status}`;
}

function setConnectionStatus(connId, status) {
    const conn = document.getElementById(connId);
    conn.className = `connection ${status}`;
}

function simulateAttack(attackType) {
    addLog(`${attackType} 공격 감지됨!`, 'warning');
    setNodeStatus('attacker', 'danger');
    setConnectionStatus('conn3', 'attack');
    
    // 트래픽 증가
    currentTraffic = Math.floor(Math.random() * 500 + 100);
    attackCounter++;
    
    // 머신러닝 탐지 시뮬레이션
    setTimeout(() => {
        if (document.getElementById('ml-detection').checked) {
            addLog('머신러닝 모델이 이상 패턴 탐지', 'warning');
            
            setTimeout(() => {
                if (document.getElementById('auto-block').checked) {
                    addLog('자동 IP 차단 규칙 적용', 'info');
                    blockedIPs++;
                    setNodeStatus('attacker', 'warning');
                }
                
                if (document.getElementById('flow-control').checked) {
                    addLog('플로우 테이블 동적 조정 완료', 'info');
                    setConnectionStatus('conn3', 'active');
                }
                
                setTimeout(() => {
                    addLog('공격 차단 완료 - 네트워크 정상화', 'info');
                    setNodeStatus('attacker', 'safe');
                    setConnectionStatus('conn3', '');
                    currentTraffic = Math.floor(Math.random() * 50 + 10);
                }, 2000);
            }, 1500);
        }
    }, 1000);
}

function startAttackSimulation() {
    if (simulationActive) return;
    
    const selectedAttacks = [];
    const attackTypes = ['ddos', 'port-scan', 'mitm', 'flow-table'];
    const attackNames = {
        'ddos': 'DDoS',
        'port-scan': '포트 스캔',
        'mitm': '중간자',
        'flow-table': '플로우 테이블 오버플로우'
    };
    
    attackTypes.forEach(type => {
        if (document.getElementById(type).checked) {
            selectedAttacks.push(attackNames[type]);
        }
    });
    
    if (selectedAttacks.length === 0) {
        alert('최소 하나의 공격 시나리오를 선택해주세요.');
        return;
    }
    
    simulationActive = true;
    document.querySelector('.start-button').disabled = true;
    document.querySelector('.start-button').textContent = '시뮬레이션 실행중...';
    
    addLog('공격 시뮬레이션 시작', 'info');
    
    // 초기 네트워크 활성화
    setConnectionStatus('conn1', 'active');
    setConnectionStatus('conn2', 'active');
    
    let attackIndex = 0;
    const attackInterval = setInterval(() => {
        if (attackIndex < selectedAttacks.length) {
            simulateAttack(selectedAttacks[attackIndex]);
            attackIndex++;
        } else {
            clearInterval(attackInterval);
            setTimeout(() => {
                addLog('모든 공격 시뮬레이션 완료', 'info');
                simulationActive = false;
                document.querySelector('.start-button').disabled = false;
                document.querySelector('.start-button').textContent = '공격 시뮬레이션 시작';
            }, 3000);
        }
        updateStats();
    }, 5000);
}

// 초기 상태 업데이트
setInterval(updateStats, 1000);