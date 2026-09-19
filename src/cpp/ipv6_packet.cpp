#include "ipv6_packet.h"

#include "c/ip_parser.h"
#include "icmp_packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"

namespace {

const char* next_header_name(uint8_t next_header) {
    switch (next_header) {
        case IP_PROTO_TCP:
            return "TCP";
        case IP_PROTO_UDP:
            return "UDP";
        case IP_PROTO_ICMPV6:
            return "ICMPv6";
        default:
            return nullptr;
    }
}
}  // namespace

Ipv6Packet::Ipv6Packet(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
                       const eth_header_t& eth, const ipv6_header_t& ipv6,
                       std::optional<tcp_header_t> tcp, std::optional<udp_header_t> udp,
                       std::optional<icmp_header_t> icmp)
    : Packet(ts_seconds, ts_microseconds, capture_length, eth),
      ipv6_(ipv6),
      tcp_(tcp),
      udp_(udp),
      icmp_(icmp) {}

const char* Ipv6Packet::protocol_name() const noexcept {
    if (tcp_.has_value())
        return "TCP";
    if (udp_.has_value())
        return "UDP";
    if (icmp_.has_value())
        return "ICMPv6";
    return "IPv6";
}

void Ipv6Packet::print(std::ostream& os) const {
    Packet::print(os);

    char src[IPV6_ADDR_STR_LEN];
    char dst[IPV6_ADDR_STR_LEN];
    ipv6_addr_to_str(ipv6_.src_addr, src);
    ipv6_addr_to_str(ipv6_.dst_addr, dst);

    os << " " << src << " > " << dst << " hop=" << static_cast<int>(ipv6_.hop_limit);

    if (tcp_.has_value()) {
        print_tcp_summary(os, *tcp_);
        return;
    }
    if (udp_.has_value()) {
        /* checksum_mandatory=true: RFC 2460 SS8.1 has no RFC 768-style
           zero-checksum exemption over IPv6. */
        print_udp_summary(os, *udp_, /*checksum_mandatory=*/true);
        return;
    }
    if (icmp_.has_value()) {
        print_icmp_summary(os, *icmp_, /*is_icmpv6=*/true);
        return;
    }

    if (const char* name = next_header_name(ipv6_.next_header)) {
        os << " next=" << name;
    } else {
        os << " next=" << static_cast<int>(ipv6_.next_header);
    }
}
