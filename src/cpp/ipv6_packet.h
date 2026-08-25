#pragma once
#include "packet.h"

#include "c/ipv6_parser.h"

class Ipv6Packet : public Packet {
public:
    Ipv6Packet(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
        const eth_header_t& eth, const ipv6_header_t& ipv6);

    const ipv6_header_t& ipv6() const noexcept { return ipv6_; }

    const char* protocol_name() const noexcept override { return "IPv6"; }
    void print(std::ostream& os) const override;

private:
    ipv6_header_t ipv6_;
};
