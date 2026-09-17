#include "udp_packet.h"

void print_udp_summary(std::ostream& os, const udp_header_t& udp, bool checksum_mandatory) {
    os << " " << udp.src_port << " > " << udp.dst_port << " len=" << udp.length;

    bool report_bad =
        checksum_mandatory ? !udp.checksum_valid : (udp.checksum_present && !udp.checksum_valid);
    if (report_bad) {
        os << " udp_csum=BAD";
    }
}

UDPPacket::UDPPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
                     const eth_header_t& eth, const ip_header_t& ip, const udp_header_t& udp)
    : Packet(ts_seconds, ts_microseconds, capture_length, eth, ip), udp_(udp) {}

void UDPPacket::print(std::ostream& os) const {
    Packet::print(os);
    print_udp_summary(os, udp_);
}
