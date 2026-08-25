#include "ipv6_packet.h"

#include "c/ip_parser.h"

namespace {
    constexpr uint8_t IPV6_NEXT_ICMPV6 = 58;

    const char* next_header_name(uint8_t next_header) {
        switch (next_header) {
            case IP_PROTO_TCP: return "TCP";
            case IP_PROTO_UDP: return "UDP";
            case IPV6_NEXT_ICMPV6: return "ICMPv6";
            default: return nullptr;
        }
    }
}

Ipv6Packet::Ipv6Packet(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
    const eth_header_t& eth, const ipv6_header_t& ipv6)
    : Packet(ts_seconds, ts_microseconds, capture_length, eth), ipv6_(ipv6) {
}

void Ipv6Packet::print(std::ostream& os) const {
    Packet::print(os);

    char src[IPV6_ADDR_STR_LEN];
    char dst[IPV6_ADDR_STR_LEN];
    ipv6_addr_to_str(ipv6_.src_addr, src);
    ipv6_addr_to_str(ipv6_.dst_addr, dst);

    os << " " << src << " > " << dst << " hop=" << static_cast<int>(ipv6_.hop_limit);

    if (const char* name = next_header_name(ipv6_.next_header)) {
        os << " next=" << name;
    }
    else {
        os << " next=" << static_cast<int>(ipv6_.next_header);
    }
}
