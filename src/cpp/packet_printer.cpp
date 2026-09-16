#include "packet_printer.h"

#include "c/arp_parser.h"
#include "c/eth_parser.h"
#include "c/ip_parser.h"
#include "c/ipv6_parser.h"
#include "c/tcp_udp_parser.h"
#include "arp_packet.h"
#include "ipv6_packet.h"
#include "packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"

#include <cctype>
#include <cstdio>

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

}

void print_packet(std::ostream& os, const uint8_t* packet, uint32_t length,
    uint32_t ts_seconds, uint32_t ts_microseconds, uint64_t packet_number) {

    os << "[#" << packet_number << "] ";

    eth_header_t eth;
    const uint8_t* eth_payload = nullptr;
    uint32_t eth_playload_len = 0;

    if (eth_parse(packet, length, &eth, &eth_payload, &eth_playload_len) != 0) {
        os << "(truncated Ethernet frame)\n";
        hex_dump(os, packet, length);
        return;
    }

    if (eth.ether_type == ETH_TYPE_ARP) {
        arp_header_t arp;
        if (arp_parse(eth_payload, eth_playload_len, &arp) == 0) {
            ArpPacket pkt(ts_seconds, ts_microseconds, length, eth, arp);
            pkt.print(os);
        }
        else {
            Packet pkt(ts_seconds, ts_microseconds, length, eth);
            pkt.print(os);
            os << " ARP (truncated)";
        }
        os << "\n";
        hex_dump(os, packet, length);
        return;
    }

    if (eth.ether_type == ETH_TYPE_IPV6) {
        ipv6_header_t ipv6;
        if (ipv6_parse(eth_payload, eth_playload_len, &ipv6, nullptr, nullptr) == 0) {
            Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6);
            pkt.print(os);
        }
        else {
            Packet pkt(ts_seconds, ts_microseconds, length, eth);
            pkt.print(os);
            os << " IPv6 (truncated)";
        }
        os << "\n";
        hex_dump(os, packet, length);
        return;
    }

    if (eth.ether_type != ETH_TYPE_IPV4) {
        Packet pkt(ts_seconds, ts_microseconds, length, eth);
        pkt.print(os);
        os << "\n";
        hex_dump(os, packet, length);
        return;
    }

    ip_header_t ip;
    const uint8_t* ip_paylaod = nullptr;
    uint32_t ip_payload_len = 0;
    if (ip_parse(eth_payload, eth_playload_len, &ip, &ip_paylaod, &ip_payload_len) != 0) {
        os << "(truncated IPv4 header)\n";
        hex_dump(os, packet, length);
        return;
    }

    switch (ip.protocol) {
        case IP_PROTO_TCP: {
            tcp_header_t tcp;
            if (tcp_parse(ip_paylaod, ip_payload_len, &tcp, nullptr, nullptr) == 0) {
                tcp.checksum_valid = (uint8_t)tcp_verify_checksum(ip_paylaod, ip_payload_len,
                    ip.src_addr, ip.dst_addr);
                TCPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, tcp);
                pkt.print(os);
            }
            else {
                Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                pkt.print(os);
                os << " TCP (truncated)";
            }
            break;
        }
        case IP_PROTO_UDP: {
            udp_header_t udp;
            if (udp_parse(ip_paylaod, ip_payload_len, &udp, nullptr, nullptr) == 0) {
                udp.checksum_valid = (uint8_t)udp_verify_checksum(ip_paylaod, ip_payload_len,
                    ip.src_addr, ip.dst_addr);
                UDPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, udp);
                pkt.print(os);
            }
            else {
                Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                pkt.print(os);
                os << " UDP (truncated)";
            }
            break;
        }
        default: {
            Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
            pkt.print(os);
            if (ip.protocol == IP_PROTO_ICMP) {
                os << " ICMP";
            }
            else {
                os << " proto=" << static_cast<int>(ip.protocol);
            }
            break;
        }
    }
    os << "\n";
    hex_dump(os, packet, length);
}

void packet_printer_callback(const uint8_t* packet, uint32_t length,
    uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data) {
    auto* ctx = static_cast<PacketPrinterContext*>(user_data);
    ++ctx->count;
    print_packet(ctx->os, packet, length, ts_seconds, ts_microseconds, ctx->count);
}
