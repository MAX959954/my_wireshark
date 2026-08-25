#pragma once
#include "packet.h"

#include "c/tcp_udp_parser.h"

class TCPPacket : public Packet {
public:
    TCPPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
        const eth_header_t& eth, const ip_header_t& ip, const tcp_header_t& tcp);

    const tcp_header_t& tcp() const noexcept { return tcp_; }

    const char* protocol_name() const noexcept override { return "TCP"; }
    void print(std::ostream& os) const override;

private:
    tcp_header_t tcp_;
};
