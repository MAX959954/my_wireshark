#pragma once
#include <cstdint>
#include <optional>
#include <ostream>

#include "c/eth_parser.h"
#include "c/ip_parser.h"

// Base class for every captured frame. Holds what every frame has
// (timestamp, raw length, Ethernet header) plus an optional IP header,
// since not every Ethernet frame carries IPv4 (ARP, IPv6, ...) and not
// every IPv4 datagram carries a TCP/UDP segment we managed to parse
// (ICMP, truncated segment, unknown protocol). TCPPacket/UDPPacket add
// the transport-layer details on top.

class Packet {
public :
	Packet(uint32_t  ts_seconds, uint32_t ts_microseconds, uint32_t  capture_length,
		const eth_header_t& eth, std::optional<ip_header_t> ip = std::nullopt);

	virtual ~Packet() = default;

	uint32_t  timestamp_secods() const noexcept { return ts_seconds_; }
	uint32_t timestamp_microseconds()  const noexcept {return ts_microseconds_;}
	uint32_t capture_length() const noexcept { return capture_length_; }
	
	const eth_header_t& ethernet() const noexcept { return eth_; }
	bool has_ip() const noexcept { return ip_.has_value(); }

	const ip_header_t& ip() const { return *ip_; }

	virtual const char* protocol_name() const noexcept { return has_ip() ? "IP" : "ETH"; }

	// Writes a one-line summary. Derived classes call Packet::print() first,
	// then append their own transport-layer fields
	virtual void print(std::ostream& os) const;

private :
	uint32_t ts_seconds_;
	uint32_t ts_microseconds_;
	uint32_t capture_length_;
	eth_header_t eth_;
	std::optional<ip_header_t> ip_;
};