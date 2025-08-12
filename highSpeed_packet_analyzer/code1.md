# include
```cpp
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <iomanip>

using namespace std;
```
> 필요 라이브러리 추가
- thread: 멀티스레드 프로그래밍을 위한 기능 제공, 패킷 처리를 별도 스레드로 실행
- mutex: 멀티스레딩 시 스레드 간 Syhchronize 문제를 위한 동기화 도구
```cpp
lock_guard<mutex> lock(queue_mutex_); // packet_queue_ 접근 시 동기화
```
- atomic: Lock 없이 안전한 변수 업데이트 가능, 패킷-바이트 수 카운트 시 race condition 방지
```cpp
total_packets_.fetch_add(1, memory_order_relaxed);
total_bytes.fetch_add(pkthdr->len, memory_order_relaxed);
```
- chrono: 시간 측정, 지연, 단위 변환 용도. 패킷 처리 속도를 측정
- memory: shared_ptr, unique_ptr와 같은 스마트 포인터, 메모리 자동 해제 지원
```cpp
auto packet_info = make_shared<PacketInfo>(); // 동적 할당된 PacketInfo 객체를 공유 포인터로 관리
```
- pcap.h: 패킷 캡처 라이브러리 인터페이스 (pcap_loop, pcap_pkthdr 등)
- netinet/ip.h: IPv4 헤더 구조체 (struct iphdr), IP 프로토콜 번호 상수
```cpp
const struct iphdr* ip_header = reinterpret_cast<const struct iphdr*>(); // IP 헤더 파싱, IP주소와 프로토콜 정보 추출
```
- netinet/tcp.h: TCP 헤더 구조체 (struct tcphdr), 포트 번호와 TCP 플래그 정보
```cpp
const struct tcphdr* tch_header = reinterpret_cast<const struct tcphdr*>(); // TCP 패킷의 source/destination 포트 추출
```
- netinet/if_ether.h: Ethernet 헤더 구조체 (struct ethhdr), ETH_P_IP 상수
```cpp
const struct ethhdr* eth_header = reinterpret_cast<const struct ethhdr*>(packet); // 이더넷 프레임의 상위 프로토콜이 IP인지 확인, 2계층 이더넷 헤더 파싱
```
- arpa/inet.h: IP 주소 변환 함수 제공 (inet_nota, inet_addr, ntohs, htons etc.)
```cpp
string src_ip = inet_ntoa(*(struct in_addr*)&ip_header->saddr); // 네트워크 바이트를 문자열로 변환
```
- algorithm: sort, find 등 정렬, 검색, 변환 알고리즘 라이브러리
- iomanip: 출력 형식 조정 라이브러리 (setw, setprecision, hex etc.)

<br>

# PacketInfo
```cpp
struct PacketInfo{
    string src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    uint32_t packet_size;
    chrono::steady_clock::time_point timestamp;

    PacketInfo(const string& s_ip, const string& d_ip, uint16_t s_port, uint16_t d_port, uint8_t proto, uint32_t size) 
        : src_ip(s_ip), dst_ip(d_ip), src_port(s_port), dst_port(d_port), protocol(proto), packet_size(size), timestamp(chrono::steady_clock::now()){}
};
```
> 개별 캡처 패킷의 정보 저장 구조체
- src_ip, dst_ip: 패킷의 송수신자 ip
- src_port, dst_port: 패킷의 송수신자 포트
- protocol: 패킷이 따르는 IP 프로토콜 번호 저장 (TCP/UDP/ICMP etc.)
- packet_size: 패킷의 크기(바이트) 저장
- timestamp: 패킷을 기록한 시점을 저장하는 타임스탬프
생성자를 통해 송/수신 IP-포트, 프로토콜, 크기를 저장하고 timestamp의 값은 현재 시각으로 설정

<br>

# FlowStats
```cpp
struct FlowStats{
    uint64_t packet_count = 0, byte_count = 0;
    chrono::steady_clock::time_point first_seen, last_seen;
    atomic<bool> is_suspicious{false};

    FlowStats() : first_seen(chrono::steady_clock::now()), last_seen(chrono::steady_clock::now()){}

    void update(uint32_t size){
        packet_count++;
        byte_count += size;
        last_seen = chrono::steady_clock::now();
    }

    double get_rate_pps() const{
        auto duration = chrono::duration_cast<chrono::seconds>(last_seen - first_seen).count();
        return duration > 0 ? static_cast<double>(packet_count) / duration : 0;
    }
};
```
> 플로우별 통계(패킷 수, 바이트 수, 시각, suspicious 여부)를 저장하는 구조체
- packet_count: 해당 플로우의 패킷 수를 저장
- byte_count: 해당 플로우의 바이트 누적합 저장
- first_seen, last_seen: 플로우를 처음 본 시점과 마지막으로 본 시점을 저장
- is_suspicious: 해당 플로우의 의심 여부를 원자적으로 저장
- FlowStats() 생성자: first_seen과 last_seen을 현재 시각으로 초기화
- update(): 플로우 통계 갱신용 멤버 함수
&emsp;패킷 수, 바이트 누적합을 증가시키고 last_seen을 현재 시각으로 초기화
- get_rate_pps(): 초당 패킷 수 (pps)를 계산하여 반환하는 멤버 함수
&emsp;duration 변수에 관측 기간(second)을 계산한 후
&emsp;기간이 0보다 클 경우 pps 계산을 하며, 아닐 경우 0을 반환

<br>

# DetectionThresholds
```cpp
struct DetectionThresholds{
    static constexpr uint64_t DDOS_PPS_THRESHOLD = 1000;
    static constexpr uint64_t DDOS_BPS_THRESHOLD = 10000000;
    static constexpr uint32_t PORT_SCAN_THRESHOLD = 20;
    static constexpr uint32_t TIME_WINDOW_SEC = 60;
};
```
> 공격 탐지용 문턱 임계값 상수 모음 구조체
- DDOS_PPS_THRESHOLD: DDoS 감지용 초당 패킷 수 1000pps
- DDOS_BPS_THRESHOLD: DDoS 감지용 초당 바이트 수 10mbps
- PORT_SCAN_THRESHOLD: Port Scan 감지용 서로 다른 목적지 포트 수 20
- TIME_WINDOW_SEC: 최근 몇 초간의 패킷을 볼 지 지정 60s

<br>

# HighSpeedPacketAnalyzer(private)
```cpp
class HighSpeedPacketAnalyzer{
private:
    unordered_map<string, FlowStats> flow_stats_;
    unordered_map<string, unordered_set<uint16_t>> port_scan_tracker_;
    unordered_map<string, vector<chrono::steady_clock::time_point>> ddos_tracker_;

    mutex stats_mutex_, scan_mutex_, ddos_mutex_;

    atomic<uint64_t> total_packets_{0}, total_bytes_{0};
    atomic<bool> running_{false};

    vector<thread> worker_threads_;
    queue<shared_ptr<PacketInfo>> packet_queue_;
    mutex queue_mutex_;
    condition_variable queue_cv_;

    pcap_t* pcap_handle_;

...

}
```
> 고속 패킷 분석 목적 클래스의 멤버 변수
- flow_stats_: key-value 쌍 unordered_map 자료형 사용하여, 플로우별 통계를 저장
- port_scan_tracker_: src_ip->dst_ip 키에 대해 접근한 목적지 포트 집합 저장
- ddos_tracker_: src IP별로 최근 패킷 타임스탬프 목록(vector)을 저장
- stats_mutex_, scan_mutex_, ddos_mutex_: 각 flow_stats_, port_scan_tracker_, ddos_tracker_의 동시 접근 보호용 뮤텍스
- total_packets_, total_bytes_: 전체 캡처 패킷 수, 바이트 수를 원자적으로 카운트 및 누적
- running_: analyzer 실행 상태를 나타내는 원자 boolean
- worker_threads_: 워커 스레드들을 저장하는 벡터
- packet_queue_: 패킷 처리 대상들의 포인터값을 저장하는 스레드 안전 큐로, 보호 시 별도의 뮤텍스로 관리
- queue_mutex_: packet_queue_의 접근 보호용 뮤텍스
- queue_cv_: 큐에 패킷이 들어올 경우 워커들을 깨우기 위한 조건 변수(cv)
- pcap_handle_: 패킷 캡처 핸들 포인터를 저장

<br>

# HighSpeedPacketAnalyzer(public) - constructor, destructor
```cpp
public:
    HighSpeedPacketAnalyzer(const string& interface) : pcap_handle_(nullptr){
        initialize_capture(interface);

        int num_threads = thread::hardware_concurrency();
        for (int i = 0; i < num_threads; i++){ // ++i, i++
            worker_threads_.emplace_back(&HighSpeedPacketAnalyzer::packet_processor, this);
        }
    }

    ~HighSpeedPacketAnalyzer(){
        stop();
        if (pcap_handle_){
            pcap_close(pcap_handle_);
        }
    }
```
> 추가 예정

---