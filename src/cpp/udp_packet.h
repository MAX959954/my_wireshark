#pragma once
#include "packet.h"

#include "c/tcp_udp_parser.h"

/*
Appends " src > dst len=... [udp_csum=BAD]" to 'os'. Shared by UDPPacket
(IPv4) and Ipv6Packet (IPv6 UDP).

'checksum_mandatory' controls how a zero checksum FIELD is reported: over
IPv4 (RFC 768) a zero field means "sender chose not to compute one" and
is not flagged even if udp.checksum_valid ended up 0 (see
udp_verify_checksum()'s own exemption); over IPv6 (RFC 2460 SS8.1) the
checksum is mandatory, so pass true there to report a zero field as bad
like any other wrong checksum.
*/
void print_udp_summary(std::ostream& os, const udp_header_t& udp, bool checksum_mandatory = false);

class UDPPacket : public Packet {
   public:
    UDPPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
              const eth_header_t& eth, const ip_header_t& ip, const udp_header_t& udp);

    const udp_header_t& udp() const noexcept {
        return udp_;
    }

    const char* protocol_name() const noexcept override {
        return "UDP";
    }
    void print(std::ostream& os) const override;

   private:
    udp_header_t udp_;
};
