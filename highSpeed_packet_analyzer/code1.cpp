#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <queue>
#include <memory>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <algorithm>
#include <iomanip>

using namespace std;

// packet information
struct PacketInfo{
    string src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    uint32_t packet_size;
    chrono::steady_clock::time_point timestamp;

    PacketInfo(const string& s_ip, const string& d_ip, uint16_t s_port, uint16_t d_port, uint8_t proto, uint32_t size) 
        : src_ip(s_ip), dst_ip(d_ip), src_port(s_port), dst_port(d_port), protocol(proto), packet_size(size), timestamp(chrono::steady_clock::now()){}
};

// flow stat information 
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
    // pkts/sec
    double get_rate_pps() const{
        auto duration = chrono::duration_cast<chrono::seconds>(last_seen - first_seen).count();
        return duration > 0 ? static_cast<double>(packet_count) / duration : 0;
    }
};

struct DetectionThresholds{
    static constexpr uint64_t DDOS_PPS_THRESHOLD = 1000; // packets/s
    static constexpr uint64_t DDOS_BPS_THRESHOLD = 10000000; // 현재 코드 사용 x
    static constexpr uint32_t PORT_SCAN_THRESHOLD = 20;
    static constexpr uint32_t TIME_WINDOW_SEC = 60;
};

class HighSpeedPacketAnalyzer{
private:
    unordered_map<string, FlowStats> flow_stats_;
    unordered_map<string, unordered_set<uint16_t>> port_scan_tracker_;
    unordered_map<string, vector<chrono::steady_clock::time_point>> ddos_tracker_;

    mutex stats_mutex_, scan_mutex_, ddos_mutex_;

    atomic<uint64_t> total_packets_{0}, total_bytes_{0};
    atomic<bool> running_{false};

    // threads
    vector<thread> worker_threads_;
    queue<shared_ptr<PacketInfo>> packet_queue_;
    mutex queue_mutex_;
    condition_variable queue_cv_;

    pcap_t* pcap_handle_;
public:
    HighSpeedPacketAnalyzer(const string& interface) : pcap_handle_(nullptr){
        initialize_capture(interface);

        int num_threads = thread::hardware_concurrency();
        for (int i = 0; i < num_threads; i++){
            worker_threads_.emplace_back(&HighSpeedPacketAnalyzer::packet_processor, this);
        }
    }

    ~HighSpeedPacketAnalyzer(){
        stop();
        if (pcap_handle_){
            pcap_close(pcap_handle_);
        }
    }

    void initialize_capture(const string& interface){
        char errbuf[PCAP_ERRBUF_SIZE];
        
        pcap_handle_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!pcap_handle_) throw runtime_error("Failed to open interface: " + string(errbuf));

        // filter setting for IP traffic
        struct bpf_program fp;
        const char* filter = "ip";
        if (pcap_compile(pcap_handle_, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) throw runtime_error("Failed to compile filter");

        if (pcap_setfilter(pcap_handle_, &fp) == -1) throw runtime_error("Failed to set filter");

        pcap_freecode(&fp);
    }

    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet){
        auto* analyzer = reinterpret_cast<HighSpeedPacketAnalyzer*>(user_data);
        analyzer->process_packet(pkthdr, packet);
    }

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

    void analyze_packet(const PacketInfo& packet){
        string flow_key = packet.src_ip + ":" + to_string(packet.src_port) + "->" + packet.dst_ip + ":" + to_string(packet.dst_port);

        // flow stat update
        {
            lock_guard<mutex> lock(stats_mutex_);
            flow_stats_[flow_key].update(packet.packet_size);
        }

        // DDoS detection
        detect_ddos_attack(packet);
        // Port scan detection
        if (packet.protocol == IPPROTO_TCP) detect_port_scan(packet);
        // anomalous traffic detection
        detect_anomalous_traffic(packet);
    }

    void detect_ddos_attack(const PacketInfo& packet){
        lock_guard<mutex> lock(ddos_mutex_);

        auto now = chrono::steady_clock::now();
        auto& timestamps = ddos_tracker_[packet.src_ip];

        // older timestamp delete
        auto cutoff_time = now - chrono::seconds(DetectionThresholds::TIME_WINDOW_SEC);
        timestamps.erase(remove_if(timestamps.begin(), timestamps.end(), [cutoff_time](const auto& ts){ return ts < cutoff_time; }), timestamps.end());

        timestamps.push_back(now);

        //DDoS threshold check
        if (timestamps.size() > DetectionThresholds::DDOS_PPS_THRESHOLD){
            cout << "[ALERT] DDoS attack detected from IP: " << packet.src_ip << " (Rate: " << timestamps.size() << " pps)" << endl;

            lock_guard<mutex> stats_lock(stats_mutex_);
            string flow_key = packet.src_ip + ":*";
            flow_stats_[flow_key].is_suspicious.store(true);
        }
    }
    void detect_port_scan(const PacketInfo& packet){
        lock_guard<mutex> lock(scan_mutex_);

        string scan_key = packet.src_ip + "->" + packet.dst_ip;
        port_scan_tracker_[scan_key].insert(packet.dst_port);

        if (port_scan_tracker_[scan_key].size() > DetectionThresholds::PORT_SCAN_THRESHOLD){ // ?? 왜 타입이 안뜨지 -> 해결 : 들여쓰기
            cout << "[ALERT] Port scan detected from " << packet.src_ip << " to " << packet.dst_ip << " (" << port_scan_tracker_[scan_key].size() << " unique ports)" << endl;
        }
    }
    
    void detect_anomalous_traffic(const PacketInfo& packet){
        // anomalous big traffic detection
        if (packet.packet_size > 9000){
            cout << "[ALERT] Unusually large packet detected: " << packet.packet_size << " bytes from " << packet.src_ip << endl;            
        }

        // not TCP, UDP, ICMP
        if (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP && packet.protocol != IPPROTO_ICMP){
            cout << "[ALERT] Unusual protocol detected: " << static_cast<int>(packet.protocol) << " from " << packet.src_ip << endl;
        }
    }

    void start(){
        running_ = true;
        cout << "Starting high-speed packet analysis..." << endl;

        pcap_loop(pcap_handle_, -1, packet_handler, reinterpret_cast<u_char*>(this));
    }
    void stop(){
        running_ = false;
        queue_cv_.notify_all();

        // worker thread finish wait
        for (auto& thread : worker_threads_){
            if (thread.joinable()) thread.join();
        }

        if (pcap_handle_) pcap_breakloop(pcap_handle_);
    }

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
            if (++count > 10) break; // only Top 10

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
}; // HighSpeedPacketAnalyzer 종료

int main(int argc, char* argv[]){
    if (argc != 2){
        cout << "Usage: " << argv[0] << " <interface>" << endl;
        cout << "Example: " << argv[0] << " eth0" << endl;
        return 1;
    }

    try{
        string interface = argv[1];
        HighSpeedPacketAnalyzer analyzer(interface);

        // 통계 출력 스레드
        thread stats_thread([&analyzer](){
            while (true){
                this_thread::sleep_for(chrono::seconds(30));
                analyzer.print_statistics();
            }
        });

        // 사용자 명령 처리 스레드
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

        analyzer.start(); //시작 : 패킷 분석
    }catch (const exception& e){
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}