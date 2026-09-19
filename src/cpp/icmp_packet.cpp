#include "icmp_packet.h"

namespace {

const char* icmp_type_name(uint8_t type, bool is_icmpv6) {
    if (is_icmpv6) {
        switch (type) {
            case ICMPV6_TYPE_DEST_UNREACHABLE:
                return "dest-unreachable";
            case ICMPV6_TYPE_PACKET_TOO_BIG:
                return "packet-too-big";
            case ICMPV6_TYPE_TIME_EXCEEDED:
                return "time-exceeded";
            default:
                return nullptr;
        }
    }
    switch (type) {
        case ICMPV4_TYPE_DEST_UNREACHABLE:
            return "dest-unreachable";
        case ICMPV4_TYPE_TIME_EXCEEDED:
            return "time-exceeded";
        default:
            return nullptr;
    }
}

}  // namespace

void print_icmp_summary(std::ostream& os, const icmp_header_t& icmp, bool is_icmpv6) {
    if (icmp.is_echo) {
        bool is_request = is_icmpv6 ? icmp.type == ICMPV6_TYPE_ECHO_REQUEST
                                    : icmp.type == ICMPV4_TYPE_ECHO_REQUEST;
        os << " " << (is_request ? "echo-request" : "echo-reply") << " id=" << icmp.echo_id
           << " seq=" << icmp.echo_seq;
    } else if (const char* name = icmp_type_name(icmp.type, is_icmpv6)) {
        os << " " << name << " code=" << static_cast<int>(icmp.code);
    } else {
        os << " type=" << static_cast<int>(icmp.type) << " code=" << static_cast<int>(icmp.code);
    }

    if (!icmp.checksum_valid) {
        os << " icmp_csum=BAD";
    }
}

IcmpPacket::IcmpPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
                       const eth_header_t& eth, const ip_header_t& ip, const icmp_header_t& icmp)
    : Packet(ts_seconds, ts_microseconds, capture_length, eth, ip), icmp_(icmp) {}

void IcmpPacket::print(std::ostream& os) const {
    Packet::print(os);
    print_icmp_summary(os, icmp_, /*is_icmpv6=*/false);
}
