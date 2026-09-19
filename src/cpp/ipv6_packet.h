#pragma once
#include <optional>

#include "packet.h"

#include "c/icmp_parser.h"
#include "c/ipv6_parser.h"
#include "c/tcp_udp_parser.h"

/*
Represents an IPv6 datagram. Unlike IPv4 (where TCP/UDP/ICMP get their
own Packet subclasses - TCPPacket/UDPPacket/IcmpPacket), the transport
header is held right here as an optional field: ipv6_parser.c only
decodes the fixed 40-byte main header, so a TCP, UDP, or ICMPv6 message
inside is either present (when packet_printer.cpp could parse one out of
next_header) or absent (an extension header, an unrecognized next
header, or a truncated segment).
*/
class Ipv6Packet : public Packet {
   public:
    Ipv6Packet(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
               const eth_header_t& eth, const ipv6_header_t& ipv6,
               std::optional<tcp_header_t> tcp = std::nullopt,
               std::optional<udp_header_t> udp = std::nullopt,
               std::optional<icmp_header_t> icmp = std::nullopt);

    const ipv6_header_t& ipv6() const noexcept {
        return ipv6_;
    }

    const char* protocol_name() const noexcept override;
    void print(std::ostream& os) const override;

   private:
    ipv6_header_t ipv6_;
    std::optional<tcp_header_t> tcp_;
    std::optional<udp_header_t> udp_;
    std::optional<icmp_header_t> icmp_;
};
