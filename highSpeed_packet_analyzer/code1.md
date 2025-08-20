# 1. include
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

# 2. PacketInfo
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

# 3. FlowStats
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

# 4. DetectionThresholds
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

# 5. HighSpeedPacketAnalyzer(private)
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

# 6. HighSpeedPacketAnalyzer(public) - constructor, destructor
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
> 고속패킷분석 클래스의 생성자와 소멸자

생성자:<br>
&emsp;인터페이스 이름을 참조받아 initialize_capture()함수를 호출하여 패킷 캡처를 초기화한다.<br>
&emsp;또한 pcap_handle_ 변수값을 null로 초기화하고, 워커 스레드를 하드웨어 코어 수만큼 생성한다.<br>
&emsp;thread::hard_ware_concurrency()를 통해 시스템의 권장 하드웨어 스레드(코어) 수를 가져오고<br>
&emsp;for 반복문을통해 worker_threads_ 벡터에 메소드 packet_processor를 실행하는 워커 스레드를 생성하여 추가한다.<br>
<br>
소멸자:<br>
&emsp;stop() 메소드를 호출하여 스레드를 정리하고,<br>
&emsp;pcap_handle_이 유효한 값일 경우 pcap_close(pcap_handle_)함수를 통해<br>
&emsp;pcap 핸들을 닫아 리소스를 해제한다.<br>
<br>

# 7. HighSpeedPacketAnalyzer(public) - initialize_capture()
```cpp
void initialize_capture(const string& interface){
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle_) throw runtime_error("Failed to open interface: " + string(errbuf));

    struct bpf_program fp;
    const char* filter = "ip";
    if (pcap_compile(pcap_handle_, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) throw runtime_error("Failed to compile filter");

    if (pcap_setfilter(pcap_handle_, &fp) == -1) throw runtime_error("Failed to set filter");

    pcap_freecode(&fp);
}
```
> 캡처 초기화 메소드, 인터페이스를 열고 필터를 설정

errbuf 문자 배열로 pcap 에러 메시지를 받을 버퍼를 생성하고<br>
pcap_open_live() 함수로 지정 인터페이스를 열어 실시간 캡처를 시작할 준비를 한다.
이를 pcap_handle_에 할당한다.<br>
<br>
pcap_handle_ 값을 통해 핸들을 여는 과정을 실패할 경우에 대한 에러 처리 구문으로
에러 메시지를 포함한 런타임 에러를 발생시킨다.<br>
<br>
bpf_program 구조체 fp를 생성한다. 이는 컴파일된 BPF 프로그램을 담을 구조체이다.<br>
filter 표현식으로 "ip" 패킷을 필터링할 문장으로 설정한다.<br>
이후 pcap_compile()으로 필터 문자열을 컴파일한 후 실패할 경우, 런타임 에러를 발생시킨다.<br>
또한 pcap_setfilter()를 통해 컴파일된 필터를 pcap 핸들에 설정한다.<br>
실패할 경우 마찬가지로 런타임 에러로 예외 처리를 진행한다.<br>
<br>
pcap_freecode(&fp);를 통해 컴파일된 BPF 프로그램 리소스를 해제하여준다.<br>
<br>

# 8. HighSpeedPacketAnalyzer(public) - packet_handler()
```cpp
static void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    auto* analyzer = reinterpret_cast<HighSpeedPacketAnalyzer*>(user_data);
    analyzer->process_packet(pkthdr, packet);
}
```
> libpcap 콜백에 쓰이는 정적 함수, pcap이 패킷을 잡을 때 호출된다.

analyzer 변수는 reinterpret_cast<>()를 통해 user_data를 HighSpeedPacketAnalyzer 포인터로 되돌린 값을 담는다.<br>
이는 생성자에서 전달된 this 포인터에 해당한다.<br>
<br>
이러한 주소값이 담긴 analyzer에서 process_packet() 메소드를 호출하여 패킷 처리를 진행한다.<br>
<br>

# 9. HighSpeedPacketAnalyzer(public) - process_packet()
```cpp
void process_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet){
    // ethernet header parsing
    const struct ethhdr* eth_header = reinterpret_cast<const struct ethhdr*>(packet);

    if (ntohs(eth_header->h_proto) != ETH_P_IP) return;
    
    // IP header parsing
    const struct iphdr* ip_header = reinterpret_cast<const struct iphdr*>(packet + sizeof(struct ethhdr));

    string src_ip = inet_ntoa(*(struct in_addr*)&ip_header->saddr);
    string dst_ip = inet_ntoa(*(struct in_addr*)&ip_header->daddr);

    uint16_t src_port = 0, dst_port = 0;

    if (ip_header->protocol == IPPROTO_TCP){
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest); 
    }else if (ip_header->protocol == IPPROTO_UDP){
        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ethhdr) + ip_header_ihl * 4);
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);
    }

    auto packet_info = make_shared<PacketInfo>(src_ip, dst_ip, src_port, dst_port, ip_header->protocol, pkthdr->len);

    {
        lock_guard<mutex> lock(queue_mutex_);
        packet_queue_.push(packet_info);
    }
    queue_cv_.notify_one();

    total_packets_.fetch_add(1, memory_order_relaxed);
    total_bytes_.fetch_add(pkthdr->len, memory_order_relaxed);
}
```
> 패킷 처리를 담당하는 메소드
- Ethernet/IP/TCP/UDP 헤더를 파싱하고
- IP 전송이 아닐 경우 드롭, 포트 추출을 진행하며
- PacketInfo 구조체를 생성하여 큐에 삽입한다.
- 총 패킷, 바이트 카운트를 증가시킨다.

```cpp
    // ethernet header parsing
    const struct ethhdr* eth_header = reinterpret_cast<const struct ethhdr*>(packet);

    if (ntohs(eth_header->h_proto) != ETH_P_IP) return;
    
    // IP header parsing
    const struct iphdr* ip_header = reinterpret_cast<const struct iphdr*>(packet + sizeof(struct ethhdr));

    string src_ip = inet_ntoa(*(struct in_addr*)&ip_header->saddr);
    string dst_ip = inet_ntoa(*(struct in_addr*)&ip_header->daddr);

    uint16_t src_port = 0, dst_port = 0;
```
이더넷 헤더를 파싱한 포인터 값을 eth_header에 reinterpret_cast<>()를 통해 담는다.<br>
이때 이더넷 타입이 IP가 아닐 경우 처리를 중단한다.<br>
다음으로 이더넷 헤더 이후 위치를 ip_header에 IP 헤더 파싱 주소값을 담는다.<br>
inet_ntoa()함수로, IP 헤더 파싱한 포인터값을 통해 소스 IP와 목적지 IP 주소를 문자열로 변환한다.<br>
이후 src_port, dst_port를 0으로 선언 및 초기화한다.<br>
<br>

```cpp
    if (ip_header->protocol == IPPROTO_TCP){
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest); 
    }else if (ip_header->protocol == IPPROTO_UDP){
        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ethhdr) + ip_header_ihl * 4);
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);
    }
```
파싱한 IP 헤더를 통해 프로토콜이 TCP인지 UDP인지에 따라 각 다음과 같은 처리를 한다.<br>
TCP일 경우:<br>
&emsp;tch_header에 TCP 헤더 위치를 계산하여 포인터 캐스팅한다. (이더넷 헤더 + IP 헤더 길이)<br>
&emsp;TCP 헤더에서 소스 포트와 목적지 포트의 값을 각각 src_port, dst_port에 할당한다.<br>
UDP일 경우:<br>
&emsp;udp_header에 UDP 헤더 위치를 TCP에서와 같은 방식으로 포인터 캐스팅한다.<br>
&emsp;이후 UDP 헤더를 통해 src_port, dst_port에 포트 값을 할당한다.<br>
<br>

```cpp
    auto packet_info = make_shared<PacketInfo>(src_ip, dst_ip, src_port, dst_port, ip_header->protocol, pkthdr->len);

    {
        lock_guard<mutex> lock(queue_mutex_);
        packet_queue_.push(packet_info);
    }
    queue_cv_.notify_one();

    total_packets_.fetch_add(1, memory_order_relaxed);
    total_bytes_.fetch_add(pkthdr->len, memory_order_relaxed);
```
packet_info에 PacketInfo 구조체를 shared_ptr로 생성한다.<br>
이후 {} 스코프를 열어 동기화를 적용한다. (워커 큐에 넣기 위해)<br>
워커 큐에 접근하기 전에 queue_mutex_를 mutex lock시킨다.<br>
이후 생성한 packet_info를 packet_queue_에 삽입하고 스코프를 닫아 lcok_guard가 범위를 벗어나 자동으로 mutex lock을 해제시킨다.<br>
다음으로 queue_cv_.notify_one() 메소드를 통해 대기중인 워커 스레드 하나를 깨워 패킷 처리를 시작하게 알린다.<br>
전체 패킷 카운트와 전체 바이트 합을 증가시키며 process_packet()함수를 종료한다.<br>
<br>

# 10. HighSpeedPacketAnalyzer(public) - packet_processor()
```cpp
void packet_processor(){
    while (running_){
        shared_ptr<PacketInfo> packet_info;

        {
            unique_lock<mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {return !packet_queue_.empty() || !running_; });

            if (!running_) break;
            if (!packet_queue_.empty()){
                packet_info = packet_queue_.front();
                packet_queue_.pop();
            }
        }

        if (packet_info) analyze_packet(*packet_info);
    }
}
```
> 워커 스레드가 실행할 패킷 처리 루프 메소드

running_의 값이 true인 동안 다음 루프를 반복한다.<br>
&emsp;packet_info를 생성하고<br>
&emsp;큐 접근을 위해 스코프를 열어 mutex lock을 적용한다.<br>
&emsp;queue_cv_.wait()으로 큐에 패킷이 있거나 running_이 false가 될 때까지 대기하며<br>
&emsp;대기 상태가 끝난 후 running_값이 false면 루프를 빠져나간다.<br>
&emsp;running_값이 false가 아니고 packet_queue가 비어있지 않으면<br>
&emsp;큐의 front 요소를 packet_info에 할당하고 pop()을 진행한다. (스코프 종료)<br>
&emsp;다음으로 packet_info가 존재한다면 analyze_packet 메소드를 호출한다.<br>
<br>

# 11. HighSpeedPacketAnalyzer(public) - analyze_packet()
```cpp
void analyze_packet(const PacketInfo& packet){
    string flow_key = packet.src_ip + ":" + to_string(packet.src_port) + "->" + packet.dst_ip + ":" + to_string(packet.dst_port);

    {
        lock_guard<mutex> lock(stats_mutex_);
        flow_stats_[flow_key].update(packet.packet_size);
    }

    detect_ddos_attack(packet);
    if (packet.protocol == IPPROTO_TCP) detect_port_scan(packet);
    detect_anomalous_traffic(packet);
}
```
> 패킷 분석 메소드, 디도스-포트 스캔-이상 트래픽 탐지 함수를 호출한다.

flow_key에 패킷의 소스-목적지 IP와 PORT 정보를 담은 문자열을 할당한다.<br>
(플로우를 구분하기 위한 문자열 키 ex - "1.2.3.4:1234->5.6.7.8:80")<br>
<br>
이후 스코프를 열어 stats_mutex_를 lock하여<br>
flow_stats_에 대한 동기화 락을 잡고 flow_key로 해당 플로우의<br>
FlowStats 구조체를 가져와 update를 호출한다. (스코프 종료 - 락 가드 종료)<br>
<br>
해당 패킷을 인자로 DDoS 탐지 메소드를 호출하고 패킷 프로토콜이 TCP일 경우<br>
포트 스캔 탐지 메소드를 추가로 호출한다.<br>
마지막으로 이상 트래픽 탐지 메소드를 호출하고 함수를 종료한다.<br>
<br>

# 12. HighSpeedPacketAnalyzer(public) - detect_ddos_attack()
```cpp
void detect_ddos_attack(const PacketInfo& packet){
    lock_guard<mutex> lock(ddos_mutex_);

    auto now = chrono::steady_clock::now();
    auto& timestamps = ddos_tracker_[packet.src_ip];

    auto cutoff_time = now - chrono::seconds(DetectionThresholds::TIME_WINDOW_SEC);
    timestamps.erase(remove_if(timestamps.begin(), timestamps.end(), [cutoff_time](const auto& ts){ return ts < cutoff_time; }), timestamps.end());

    timestamps.push_back(now);

    if (timestamps.size() > DetectionThresholds::DDOS_PPS_THRESHOLD){
        cout << "[ALERT] DDoS attack detected from IP: " << packet.src_ip << " (Rate: " << timestamps.size() << " pps)" << endl;

        lock_guard<mutex> stats_lock(stats_mutex_);
        string flow_key = packet.src_ip + ":*";
        flow_stats_[flow_key].is_suspicious.store(true);
    }
}
```
> 디도스(DDoS) 공격 탐지 메소드

소스 IP기준으로 타임스탬프를 분석하여 DDoS 의심 여부를 판단한다.<br>
<br>
lock_guard로 ddos_tracker_ 접근을 보호하기 위한 mutex lock을 건다.<br>
now에 chrono::steady_clock::now() 메소드를 통해 현재 시각을 할당한다.<br>
timestamps에 소스 IP의 타임스탬프 벡터를 참조한다.<br>
<br>
이후 cutoff_time에 현재 시각 - 지정 윈도우를 계산하여 컷오프 시간을 할당한다.<br>
이어서 timestamps 벡터에서 cutoff_time보다 큰 오래된 타임스탬프들을 제거한다.<br>
타임스탬프에 현재 시간(now)을 추가한다.<br>
<br>
if()문을 통해 최근 윈도우 내 타임스탬프 수가 설정된 PPS 문턱값보다 클 경우<br>
DDoS 탐지 알림을 표준 출력으로 알린다. (src_ip 주소와 Rate 값을 포함)<br>
<br>
flow_stats_ 접근을 위해 mutex lock을 걸고<br>
flow_stats_에서 현재 소스 IP에 맞는 플로우들의 is_suspicious 값을 true로 설정한다.<br>
<br>

# 13. HighSpeedPacketAnalyzer(public) - detect_port_scan()
```cpp
void detect_port_scan(const PacketInfo& packet){
    lock_guard<mutex> lock(scan_mutex_);

    string scan_key = packet.src_ip + "->" + packet.dst_ip;
    port_scan_tracker_[scan_key].insert(packet.dst_port);

    if (port_scan_tracker_[scan_key].size() > DetectionThresholds::PORT_SCAN_THRESHOLD){ 
        cout << "[ALERT] Port scan detected from " << packet.src_ip << " to " << packet.dst_ip << " (" << port_scan_tracker_[scan_key].size() << " unique ports)" << endl;
    }
}
```
> 포트 스캔 탐지 메소드

port_scan_tracker_ 접근을 보호하기 위해 scan_mutex_로 mutex lock을 건다.<br>
이후 scan_key 문자열을 할당 (ex - "1.2.3.4->5.6.7.8")<br>
port_scan_tracker_에 scan_key에 해당하는 키에 대해 목적지 포트를 집합에 추가한다.<br>
<br>
if()문을 통해 scan_key에 해당하는 port_scan_tracker_의 포트들의 수가 문턱값보다 클 경우<br>
포트 스캔 공격으로 간주하여 포트 스캔 탐지 문구를 표준 출력한다. (소스 IP, 목적지 IP, 고유 포트 수 포함)<br>
<br>

# 14. HighSpeedAnalyzer(public) - detect_anomalous_traffic()
```cpp
void detect_anomalous_traffic(const PacketInfo& packet){
    if (packet.packet_size > 9000){
        cout << "[ALERT] Unusually large packet detected: " << packet.packet_size << " bytes from " << packet.src_ip << endl;            
    }

    if (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP && packet.protocol != IPPROTO_ICMP){
        cout << "[ALERT] Unusual protocol detected: " << static_cast<int>(packet.protocol) << " from " << packet.src_ip << endl;
    }
}
```
> 이상 트래픽 감지 메소드 (큰 패킷, 비정상 프로토콜)

패킷의 크기가 9000 바이트보다 클 경우 경고 메시지를 표준 출력<br>
패킷의 프로토콜이 TCP, UDP, ICMP 모두 아닐 경우 경고 메시지를 표준 출력<br>
<br>

# 15. HighSpeedPacketAnalyzer(public) - start(), stop()
```cpp
    void start(){
        running_ = true;
        cout << "Starting high-speed packet analysis..." << endl;

        pcap_loop(pcap_handle_, -1, packet_handler, reinterpret_cast<u_char*>(this));
    }
    void stop(){
        running_ = false;
        queue_cv_.notify_all();

        for (auto& thread : worker_threads_){
            if (thread.joinable()) thread.join();
        }

        if (pcap_handle_) pcap_breakloop(pcap_handle_);
    }
```
> 패킷 캡처 및 분석 시작, 종료 메소드

start():<br>
&emsp;running_ 상태를 true로 설정<br>
&emsp;고속 패킷 분석 시작 표준 메시지 출력<br>
&emsp;libpcap의 pcap_loop() 메소드를 실행한다. 무한(-1)으로 패킷을 캡처하며<br>
&emsp;잡힌 패킷마다 packet_handler() 콜백함수를 호출하고 this를 user_data로 전달한다.<br>
<br>
stop():<br>
&emsp;running_ 상태를 false로 설정<br>
&emsp;queue_cv_ 조건변수를 깨워 모든 대기 중인 워커를 종료하도록 한다.<br>
&emsp;for()반복을 통해 모든 워커 스레드를 순회하며 스레드가 join 가능한 상태면<br>
&emsp;thread.join()을 통해 스레드가 종료될 때까지 현재 스레드에서 기다린다.<br>
&emsp;마지막으로 pcap_handle_이 유효할 경우 pcap_loop를 중단하는 pcap_breakloop()를 호출한다.<br>
<br>

# 16. HighSpeedPacketAnalyzer(public) - print_statistics()
```cpp
void print_statistics(){
    lock_guard<mutex> lock(stats_mutex_);

    cout << "\n=== PACKET ANALYSIS STATISTICS ===" << endl;
    cout << "Total Packets: " << total_packets_.load() << endl;
    cout << "Total Bytes: " << total_bytes_.load() << endl;

    cout << "\nTop FLows by Packet Count: " << endl;

    vector<pair<string, FlowStats*>> sorted_flows;
    for (auto& [flow_key, stats] : flow_stats_){
        sorted_flows.emplace_back(flow_key, &stats);
    }

    sort(sorted_flows.begin(), sorted_flows.end(), [](const auto& a, const auto& b){
        return a.second->packet_count > b.second->packet_count;
    });

    int count = 0;
    for (const auto& [flow_key, stats] : sorted_flows){
        if (++count > 10) break;

        cout << setw(40) << flow_key
            << " | Packets: " << setw(8) << stats->packet_count
            << " | Bytes: " << setw(10) << stats->byte_count
            << " | Rate: " << fixed << setprecision(2)
            << stats->get_rate_pps() << " pps";

        if (stats->is_suspicious.load()) cout << " [SUSPICIOUS]";
        cout << endl;
    }

    cout << "\nSuspicious IPs: ";
    bool first = true;
    for (const auto& [flow_key, stats] : flow_stats_){
        if (stats.is_suspicious.load()){
            if (!first) cout << ", ";
            cout << flow_key.substr(0, flow_key.find(':'));
            first = false;
        }
    }

    if (first) cout << "None" << endl;
}
```
> 누적된 통계(총 패킷/바이트, 상위 플로우 등)를 출력하는 메소드

```cpp
    lock_guard<mutex> lock(stats_mutex_);

    cout << "\n=== PACKET ANALYSIS STATISTICS ===" << endl;
    cout << "Total Packets: " << total_packets_.load() << endl;
    cout << "Total Bytes: " << total_bytes_.load() << endl;

    cout << "\nTop FLows by Packet Count: " << endl;

```
통계 map을 읽을 때 동기화하기 위해 stats_mutex_로 mutex lock을 건다.<br>
이후 표준 출력으로 전체 패킷 수와 전체 바이트 수를 출력하고<br>
상위 플로우 목록 헤더 출력을 알리는 메시지를 표준 출력한다.<br>
<br>

```cpp
    vector<pair<string, FlowStats*>> sorted_flows;
    for (auto& [flow_key, stats] : flow_stats_){
        sorted_flows.emplace_back(flow_key, &stats);
    }

    sort(sorted_flows.begin(), sorted_flows.end(), [](const auto& a, const auto& b){
        return a.second->packet_count > b.second->packet_count;
    });
```
플로우 키와 FlowStats의 포인터 pair쌍을 담을 벡터 sorted_flows를 선언한다.<br>
이후 flow_stats_의 모든 항목을 순회하며<br>
플로우 키와 해당 FlowStats 구조체의 주소 페어를 벡터에 추가한다.<br>
<br>
알고리즘 라이브러리의 sort()함수를 이용해 플로우의 패킷 수를 기준으로 내림차순 정렬한다.<br>
<br>

```cpp
    int count = 0;
    for (const auto& [flow_key, stats] : sorted_flows){
        if (++count > 10) break;

        cout << setw(40) << flow_key
            << " | Packets: " << setw(8) << stats->packet_count
            << " | Bytes: " << setw(10) << stats->byte_count
            << " | Rate: " << fixed << setprecision(2)
            << stats->get_rate_pps() << " pps";

        if (stats->is_suspicious.load()) cout << " [SUSPICIOUS]";
        cout << endl;
    }
```
상위 N개(10)의 플로우를 출력하기 위한 정수형 변수 count를 선언한다.<br>
이후 for()문을 통해 정렬된 sorted_flows 벡터를 순회한다.<br>
매 반복마다 카운트를 증가하며 10보다 클 경우 반복문을 종료한다.<br>
<br>
표준 출력으로 플로우 키를 넓이:witdh 40으로 정렬하여 출력한다.<br>
패킷 수와 바이트 합 PPS를 이어서 표준 출력한다.<br>
<br>
해당 플로우가 suspicious일 경우 추가 태그를 덧붙인다. ("[SUSPICIOUS]")<br>
<br>

```cpp
    cout << "\nSuspicious IPs: ";
    bool first = true;
    for (const auto& [flow_key, stats] : flow_stats_){
        if (stats.is_suspicious.load()){
            if (!first) cout << ", ";
            cout << flow_key.substr(0, flow_key.find(':'));
            first = false;
        }
    }

    if (first) cout << "None" << endl;
```
의심스러운 IP들의 리스트를 출력하기 위한 구문<br>
쉼표 포맷을 위한 first 불리언을 true로 선언 및 초기화한 후<br>
flow_stats_의 모든 플로우를 for()문으로 순회한다.<br>
플로우가 suspicious일 경우 해당 플로우의 소스 IP 부분을 substr하여 표준 출력한다.<br>
<br>
반복문 종료 후에도 first 값이 true일 경우, 의심 IP가 없는 것이기에 None을 표준 출력한다.<br>
<br>

# 17. HighSpeedPacketAnalyzer(public) - reset_statistics()
```cpp
void reset_statistics(){
    lock_guard<mutex> stats_lock(stats_mutex_);
    lock_guard<mutex> scan_lock(scan_mutex_);
    lock_guard<mutex> ddos_lock(ddos_mutex_);

    flow_stats_.clear();
    port_scan_tracker_.clear();
    ddos_tracker_.clear();
    total_packets_.store(0);
    total_bytes_.store(0);

    cout << "Statistics reset." << endl;
}
```
> 패킷 분석의 모든 통계를 초기화하는 메소드

flow_stats_, port_scan_tracker_, ddos_tracker_를 보호하는 모든 mutex lock을 실행한다.<br>
이후 flow_stats_, port_scan_tracker_, ddos_tracker_, total_packets_, total_bytes_ 값을 전부 비우고 0으로 초기화한다.<br>
<br>

# 18. main()
```cpp
int main(int argc, char* argv[]){
    if (argc != 2){
        cout << "Usage: " << argv[0] << " <interface>" << endl;
        cout << "Example: " << argv[0] << " eth0" << endl;
        return 1;
    }

    try{
        string interface = argv[1];
        HighSpeedPacketAnalyzer analyzer(interface);

        thread stats_thread([&analyzer](){
            while (true){
                this_thread::sleep_for(chrono::seconds(30));
                analyzer.print_statistics();
            }
        });

        thread command_thread([&analyzer](){
            string command;
            while (cin >> command){
                if (command == "stats") analyzer.print_statistics();
                else if (command == "reset") analyzer.reset_statistics();
                else if (command == "quit" || command == "exit"){
                    analyzer.stop();
                    exit(0);
                }else cout << "Commands: stats, reset, quit/exit" << endl;
            }
        });

        analyzer.start();
    }catch (const exception& e){
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
```
> main

```cpp
    if (argc != 2){
        cout << "Usage: " << argv[0] << " <interface>" << endl;
        cout << "Example: " << argv[0] << " eth0" << endl;
        return 1;
    }
```
인터페이스 이름을 인수로 받으며 이에 해당하는 올바른 호출 방식을 출력한다. 이후 비정상 종료한다.<br>
<br>

```cpp
    try{
        string interface = argv[1];
        HighSpeedPacketAnalyzer analyzer(interface);

        thread stats_thread([&analyzer](){
            while (true){
                this_thread::sleep_for(chrono::seconds(30));
                analyzer.print_statistics();
            }
        });

        thread command_thread([&analyzer](){
            string command;
            while (cin >> command){
                if (command == "stats") analyzer.print_statistics();
                else if (command == "reset") analyzer.reset_statistics();
                else if (command == "quit" || command == "exit"){
                    analyzer.stop();
                    exit(0);
                }else cout << "Commands: stats, reset, quit/exit" << endl;
            }
        });

        analyzer.start();
    }catch (const exception& e){
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
```
예외처리를 위한 try-catch문<br>
try:<br>
&emsp;인자로 전달된 인터페이스 이름을 interface 변수에 할당한다.<br>
&emsp;analyzer 변수명으로 HighSpeedPacketAnalyzer 객체를 생성하여 캡처 초기화 및 워커 스레드 생성을 실행한다.<br>
&emsp;통계 출력을 위한 스레드인 stats_thread를 생성하고 analyzer 객체를 참조하여<br>
&emsp;다음 람다로 동작을 정의한다.
- 명령어를 담을 문자열 변수 command 선언
- 단어 단위로 명령어를 표준 입력을 통해 command에 할당한다.
- command에 따라 stats, reset, quit/exit일 경우 이에 해당하는 analyzer 객체 메소드를 실행한다.
- analyzer 객체의 start() 메소드로 pcap_loop를 호출하여 패킷 캡처 및 분석을 시작한다.<br>
catch:<br>
&emsp;try 블록에서 예외가 발생할 경우 해당 메시지를 표준 에러로 출력하고 비정상 종료한다.<br>
이후 정상 종료한다.