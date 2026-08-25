#include "c/capture_backend.h"
#include "c/eth_parser.h"
#include "c/tcp_udp_parser.h"
#include "c/ip_parser.h"
#include "c/arp_parser.h"
#include "c/ipv6_parser.h"
#include "cpp/packet.h"
#include "cpp/tcp_packet.h"
#include "cpp/udp_packet.h"
#include "cpp/arp_packet.h"
#include "cpp/ipv6_packet.h"
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>

namespace {

    void hex_dump(std::ostream& os, const uint8_t* data, uint32_t length) {
        char line[80];
        for (uint32_t offset = 0; offset < length; offset += 16) {
            uint32_t chunk = (length - offset < 16) ? (length - offset) : 16;
            int pos = std::snprintf(line, sizeof(line), "  0x%04x:  ", offset);
            for (uint32_t i = 0; i < 16; i++) {
                if (i < chunk) {
                    pos += std::snprintf(line + pos, sizeof(line) - pos, "%02x", data[offset + i]);
                }
                else {
                    pos += std::snprintf(line + pos, sizeof(line) - pos, "  ");
                }
                if (i % 2 == 1) {
                    pos += std::snprintf(line + pos, sizeof(line) - pos, " ");
                }
            }
            os << line << ' ';
            for (uint32_t i = 0; i < chunk; i++) {
                uint8_t b = data[offset + i];
                os << (std::isprint(b) ? static_cast<char>(b) : '.');
            }
            os << "\n";
        }
    }

    void on_packet(const uint8_t* packet, uint32_t length,
        uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data) {
        auto* count = static_cast<uint64_t*> (user_data);
        ++(*count);
        std :: cout << "[#" << *count << "] ";

        eth_header_t eth;
        const uint8_t* eth_payload = nullptr;
        uint32_t eth_playload_len = 0;

        if (eth_parse(packet , length , &eth , &eth_payload , &eth_playload_len) != 0) {
            std::cout << "(truncated Ethernet frame)\n";
            hex_dump(std::cout, packet, length);
            return;
        }

        if (eth.ether_type == ETH_TYPE_ARP) {
            arp_header_t arp;
            if (arp_parse(eth_payload, eth_playload_len, &arp) == 0) {
                ArpPacket pkt(ts_seconds, ts_microseconds, length, eth, arp);
                pkt.print(std::cout);
            }
            else {
                Packet pkt(ts_seconds, ts_microseconds, length, eth);
                pkt.print(std::cout);
                std::cout << " ARP (truncated)";
            }
            std::cout << "\n";
            hex_dump(std::cout, packet, length);
            return;
        }

        if (eth.ether_type == ETH_TYPE_IPV6) {
            ipv6_header_t ipv6;
            if (ipv6_parse(eth_payload, eth_playload_len, &ipv6, nullptr, nullptr) == 0) {
                Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6);
                pkt.print(std::cout);
            }
            else {
                Packet pkt(ts_seconds, ts_microseconds, length, eth);
                pkt.print(std::cout);
                std::cout << " IPv6 (truncated)";
            }
            std::cout << "\n";
            hex_dump(std::cout, packet, length);
            return;
        }

        if (eth.ether_type != ETH_TYPE_IPV4) {
            Packet pkt(ts_seconds, ts_microseconds, length, eth);
            pkt.print(std::cout);
            std::cout << "\n";
            hex_dump(std::cout, packet, length);
            return;
        }

        ip_header_t ip;
        const uint8_t* ip_paylaod = nullptr;
        uint32_t ip_payload_len = 0;
        if (ip_parse(eth_payload , eth_playload_len , &ip , &ip_paylaod , &ip_payload_len) != 0 ) {
            std::cout << "(truncated IPv4 header)\n";
            hex_dump(std::cout, packet, length);
            return;
        }

        switch (ip.protocol) {
            case IP_PROTO_TCP: {
                tcp_header_t tcp;
                if (tcp_parse(ip_paylaod , ip_payload_len , &tcp , nullptr , nullptr )== 0) {
                    tcp.checksum_valid = (uint8_t)tcp_verify_checksum(ip_paylaod, ip_payload_len,
                        ip.src_addr, ip.dst_addr);
                    TCPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, tcp);
                    pkt.print(std::cout);
                }
                else {
                    Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                    pkt.print(std::cout);
                    std::cout << " TCP (truncated)";
                }
                break;
            }
            case IP_PROTO_UDP: {
                udp_header_t udp;
                if (udp_parse(ip_paylaod, ip_payload_len, &udp, nullptr, nullptr) == 0) {
                    udp.checksum_valid = (uint8_t)udp_verify_checksum(ip_paylaod, ip_payload_len,
                        ip.src_addr, ip.dst_addr);
                    UDPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, udp);
                    pkt.print(std::cout);
                }
                else {
                    Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                    pkt.print(std::cout);
                    std::cout << " UDP (truncated)";
                }
                break;
            }
            default: {
                Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                pkt.print(std::cout);
                if (ip.protocol == IP_PROTO_ICMP) {
                    std::cout << " ICMP";
                }
                else {
                    std::cout << " proto=" << static_cast<int>(ip.protocol);
                }
                break;
            }
        }
        std::cout << "\n";
        hex_dump(std::cout, packet, length);
    }
}

namespace {

    void print_usage(const char* argv0) {
        std::cerr << "Usage: " << argv0 << " [-i <iface>] [-f \"<bpf filter>\"] [-w <out.pcap>]\n"
            "  -i  capture device name (skips the interactive interface prompt)\n"
            "  -f  BPF filter, e.g. \"tcp port 443\"\n"
            "  -w  write captured packets to this .pcap file\n"
            "With no -i, falls back to the interactive interface picker.\n";
    }

}

int main(int argc, char** argv) {
    std::string cli_iface;
    std::string cli_filter;
    std::string cli_pcap_path;
    bool have_iface = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            cli_iface = argv[++i];
            have_iface = true;
        }
        else if (arg == "-f" && i + 1 < argc) {
            cli_filter = argv[++i];
        }
        else if (arg == "-w" && i + 1 < argc) {
            cli_pcap_path = argv[++i];
        }
        else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    capture_device_t devices[CAPTURE_MAX_DEVICES];
    int device_count = capture_backend_list_devices(devices, CAPTURE_MAX_DEVICES);

    if (device_count <= 0) {
        std::cerr << "No capture devices found. Raw packet capture requires "
            "CAP_NET_RAW (run as root, or `sudo setcap cap_net_raw+ep <binary>`).\n";
        return 1;
    }

    std::string device_name;
    std::string filter = cli_filter;
    std::string pcap_path = cli_pcap_path;

    if (have_iface) {
        device_name = cli_iface;
    }
    else {
        std::cout << "Available interfaces : \n";
        for (int i = 0; i < device_count; i++) {
            std::cout << "  [" << i << "] " << devices[i].name << "\n";
        }

        std::cout << "Select interface index : ";
        int choice = -1;
        std::cin >> choice;

        if (choice < 0 || choice >= device_count) {
            std::cerr << "Invalid choice";
            return 1;
        }
        device_name = devices[choice].name;

        std::cout << "BPF filter (empty = none): ";
        std::cin.ignore();
        std::getline(std::cin, filter);

        std::cout << "Save to .pcap file (empty = don't save): ";
        std::getline(std::cin, pcap_path);
    }

    std::cout << "Capturing on " << device_name << " (Ctrl+C to stop)...\n";
    uint64_t packet_count = 0;
    if (capture_backend_run(device_name.c_str(), filter.c_str(), pcap_path.c_str(), on_packet, &packet_count) != 0) {
        std::cerr << "Capturing failed\n";
        return 1;
    }
}
