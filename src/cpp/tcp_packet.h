#pragma once
#include "packet.h"

#include "c/tcp_udp_parser.h"

/*
Appends " src > dst seq=... ack=... flags=[...] [tcp_csum=BAD]" to 'os'.
Shared by TCPPacket (IPv4) and Ipv6Packet (IPv6 TCP) so a TCP segment's
summary line looks identical regardless of which IP version carried it.
*/
void print_tcp_summary(std::ostream& os, const tcp_header_t& tcp);

class TCPPacket : public Packet {
   public:
    TCPPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
              const eth_header_t& eth, const ip_header_t& ip, const tcp_header_t& tcp);

    const tcp_header_t& tcp() const noexcept {
        return tcp_;
    }

    const char* protocol_name() const noexcept override {
        return "TCP";
    }
    void print(std::ostream& os) const override;

   private:
    tcp_header_t tcp_;
};
