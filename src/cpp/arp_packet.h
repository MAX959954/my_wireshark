#pragma once
#include "packet.h"

#include "c/arp_parser.h"

class ArpPacket : public Packet {
public:
    ArpPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
        const eth_header_t& eth, const arp_header_t& arp);

    const arp_header_t& arp() const noexcept { return arp_; }

    const char* protocol_name() const noexcept override { return "ARP"; }
    void print(std::ostream& os) const override;

private:
    arp_header_t arp_;
};
