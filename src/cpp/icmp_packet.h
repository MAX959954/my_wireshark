#pragma once
#include "packet.h"

#include "c/icmp_parser.h"

/*
Appends " echo-request id=.. seq=.." / " echo-reply id=.. seq=.." for a
ping, or " <type-name> code=N" / " type=N code=N" for anything else,
plus " icmp_csum=BAD" when invalid. Shared by IcmpPacket (ICMPv4, over
IPv4) and Ipv6Packet (ICMPv6, over IPv6) so a ping's summary line looks
the same regardless of IP version - see print_tcp_summary()/
print_udp_summary() for the same sharing pattern with TCP/UDP.
*/
void print_icmp_summary(std::ostream& os, const icmp_header_t& icmp, bool is_icmpv6);

class IcmpPacket : public Packet {
   public:
    IcmpPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
               const eth_header_t& eth, const ip_header_t& ip, const icmp_header_t& icmp);

    const icmp_header_t& icmp() const noexcept {
        return icmp_;
    }

    const char* protocol_name() const noexcept override {
        return "ICMP";
    }
    void print(std::ostream& os) const override;

   private:
    icmp_header_t icmp_;
};
