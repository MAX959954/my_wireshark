#include "packet_printer.h"

#include "c/arp_parser.h"
#include "c/eth_parser.h"
#include "c/icmp_parser.h"
#include "c/ip_parser.h"
#include "c/ipv6_parser.h"
#include "c/tcp_udp_parser.h"
#include "arp_packet.h"
#include "icmp_packet.h"
#include "ipv6_packet.h"
#include "packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <optional>

namespace {

void hex_dump(std::ostream& os, const uint8_t* data, uint32_t length) {
    char line[80];
    for (uint32_t offset = 0; offset < length; offset += 16) {
        uint32_t chunk = (length - offset < 16) ? (length - offset) : 16;
        int pos = std::snprintf(line, sizeof(line), "  0x%04x:  ", offset);
        for (uint32_t i = 0; i < 16; i++) {
            if (i < chunk) {
                pos += std::snprintf(line + pos, sizeof(line) - pos, "%02x", data[offset + i]);
            } else {
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

}  // namespace

void print_packet(std::ostream& os, const uint8_t* packet, uint32_t length, uint32_t ts_seconds,
                  uint32_t ts_microseconds, uint64_t packet_number, const dispfilter_t* filter) {
    // Filled in as parsing descends through the layers below, then matched
    // against 'filter' (if any) right before a packet is actually printed -
    // see the header comment on print_packet() / dispfilter.h.
    dispfilter_fields_t fields;
    std::memset(&fields, 0, sizeof(fields));

    auto passes_filter = [&]() {
        return filter == nullptr || dispfilter_matches(filter, &fields) != 0;
    };

    // Prints 'message' verbatim (used for the two "couldn't even parse this
    // much" fallbacks below, which have no Packet object to format).
    auto finish_raw = [&](const char* message) {
        if (!passes_filter()) {
            return;
        }
        os << "[#" << packet_number << "] " << message << "\n";
        hex_dump(os, packet, length);
    };

    // Prints 'pkt's own summary (plus an optional trailing note, e.g.
    // " TCP (truncated)") and the hex dump - the common path for every
    // successfully-decoded-at-least-partially frame.
    auto finish = [&](const Packet& pkt, const char* suffix = nullptr) {
        if (!passes_filter()) {
            return;
        }
        os << "[#" << packet_number << "] ";
        pkt.print(os);
        if (suffix != nullptr) {
            os << suffix;
        }
        os << "\n";
        hex_dump(os, packet, length);
    };

    eth_header_t eth;
    const uint8_t* eth_payload = nullptr;
    uint32_t eth_playload_len = 0;

    if (eth_parse(packet, length, &eth, &eth_payload, &eth_playload_len) != 0) {
        finish_raw("(truncated Ethernet frame)");
        return;
    }

    std::memcpy(fields.eth_src, eth.src_mac, ETH_ADDR_LEN);
    std::memcpy(fields.eth_dst, eth.dst_mac, ETH_ADDR_LEN);

    if (eth.ether_type == ETH_TYPE_ARP) {
        arp_header_t arp;
        if (arp_parse(eth_payload, eth_playload_len, &arp) == 0) {
            ArpPacket pkt(ts_seconds, ts_microseconds, length, eth, arp);
            finish(pkt);
        } else {
            Packet pkt(ts_seconds, ts_microseconds, length, eth);
            finish(pkt, " ARP (truncated)");
        }
        return;
    }

    if (eth.ether_type == ETH_TYPE_IPV6) {
        ipv6_header_t ipv6;
        const uint8_t* ipv6_payload = nullptr;
        uint32_t ipv6_payload_len = 0;
        if (ipv6_parse(eth_payload, eth_playload_len, &ipv6, &ipv6_payload, &ipv6_payload_len) ==
            0) {
            fields.has_ipv6 = 1;
            std::memcpy(fields.ipv6_src, ipv6.src_addr, IPV6_ADDR_LEN);
            std::memcpy(fields.ipv6_dst, ipv6.dst_addr, IPV6_ADDR_LEN);

            switch (ipv6.next_header) {
                case IP_PROTO_TCP: {
                    tcp_header_t tcp;
                    if (tcp_parse(ipv6_payload, ipv6_payload_len, &tcp, nullptr, nullptr) == 0) {
                        tcp.checksum_valid = (uint8_t)tcp_verify_checksum_ipv6(
                            ipv6_payload, ipv6_payload_len, ipv6.src_addr, ipv6.dst_addr);
                        fields.has_tcp = 1;
                        fields.tcp_src_port = tcp.src_port;
                        fields.tcp_dst_port = tcp.dst_port;
                        Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6, tcp);
                        finish(pkt);
                    } else {
                        Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6);
                        finish(pkt, " TCP (truncated)");
                    }
                    break;
                }
                case IP_PROTO_UDP: {
                    udp_header_t udp;
                    if (udp_parse(ipv6_payload, ipv6_payload_len, &udp, nullptr, nullptr) == 0) {
                        udp.checksum_valid = (uint8_t)udp_verify_checksum_ipv6(
                            ipv6_payload, ipv6_payload_len, ipv6.src_addr, ipv6.dst_addr);
                        fields.has_udp = 1;
                        fields.udp_src_port = udp.src_port;
                        fields.udp_dst_port = udp.dst_port;
                        Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6, std::nullopt,
                                       udp);
                        finish(pkt);
                    } else {
                        Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6);
                        finish(pkt, " UDP (truncated)");
                    }
                    break;
                }
                case IP_PROTO_ICMPV6: {
                    icmp_header_t icmp;
                    if (icmp_parse(ipv6_payload, ipv6_payload_len, ICMP_FAMILY_V6, &icmp) == 0) {
                        icmp.checksum_valid = (uint8_t)icmpv6_verify_checksum(
                            ipv6_payload, ipv6_payload_len, ipv6.src_addr, ipv6.dst_addr);
                        Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6, std::nullopt,
                                       std::nullopt, icmp);
                        finish(pkt);
                    } else {
                        Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6);
                        finish(pkt, " ICMPv6 (truncated)");
                    }
                    break;
                }
                default: {
                    Ipv6Packet pkt(ts_seconds, ts_microseconds, length, eth, ipv6);
                    finish(pkt);
                    break;
                }
            }
        } else {
            Packet pkt(ts_seconds, ts_microseconds, length, eth);
            finish(pkt, " IPv6 (truncated)");
        }
        return;
    }

    if (eth.ether_type != ETH_TYPE_IPV4) {
        Packet pkt(ts_seconds, ts_microseconds, length, eth);
        finish(pkt);
        return;
    }

    ip_header_t ip;
    const uint8_t* ip_paylaod = nullptr;
    uint32_t ip_payload_len = 0;
    if (ip_parse(eth_payload, eth_playload_len, &ip, &ip_paylaod, &ip_payload_len) != 0) {
        finish_raw("(truncated IPv4 header)");
        return;
    }

    fields.has_ip = 1;
    std::memcpy(fields.ip_src, ip.src_addr, IP_ADDR_LEN);
    std::memcpy(fields.ip_dst, ip.dst_addr, IP_ADDR_LEN);

    switch (ip.protocol) {
        case IP_PROTO_TCP: {
            tcp_header_t tcp;
            if (tcp_parse(ip_paylaod, ip_payload_len, &tcp, nullptr, nullptr) == 0) {
                tcp.checksum_valid = (uint8_t)tcp_verify_checksum(ip_paylaod, ip_payload_len,
                                                                  ip.src_addr, ip.dst_addr);
                fields.has_tcp = 1;
                fields.tcp_src_port = tcp.src_port;
                fields.tcp_dst_port = tcp.dst_port;
                TCPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, tcp);
                finish(pkt);
            } else {
                Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                finish(pkt, " TCP (truncated)");
            }
            break;
        }
        case IP_PROTO_UDP: {
            udp_header_t udp;
            if (udp_parse(ip_paylaod, ip_payload_len, &udp, nullptr, nullptr) == 0) {
                udp.checksum_valid = (uint8_t)udp_verify_checksum(ip_paylaod, ip_payload_len,
                                                                  ip.src_addr, ip.dst_addr);
                fields.has_udp = 1;
                fields.udp_src_port = udp.src_port;
                fields.udp_dst_port = udp.dst_port;
                UDPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, udp);
                finish(pkt);
            } else {
                Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                finish(pkt, " UDP (truncated)");
            }
            break;
        }
        case IP_PROTO_ICMP: {
            icmp_header_t icmp;
            if (icmp_parse(ip_paylaod, ip_payload_len, ICMP_FAMILY_V4, &icmp) == 0) {
                icmp.checksum_valid = (uint8_t)icmpv4_verify_checksum(ip_paylaod, ip_payload_len);
                IcmpPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, icmp);
                finish(pkt);
            } else {
                Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
                finish(pkt, " ICMP (truncated)");
            }
            break;
        }
        default: {
            Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
            char suffix[32];
            // sized well beyond " proto=255" (ip.protocol is a uint8_t), so
            // this can never truncate - the return value isn't worth
            // checking (cert-err33-c).
            (void)std::snprintf(suffix, sizeof(suffix), " proto=%d", static_cast<int>(ip.protocol));
            finish(pkt, suffix);
            break;
        }
    }
}

void packet_printer_callback(const uint8_t* packet, uint32_t length, uint32_t ts_seconds,
                             uint32_t ts_microseconds, void* user_data) {
    auto* ctx = static_cast<PacketPrinterContext*>(user_data);
    ++ctx->count;
    print_packet(ctx->os, packet, length, ts_seconds, ts_microseconds, ctx->count, ctx->filter);
}
