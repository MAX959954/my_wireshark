#pragma once
#include "packet.h"

#include "c/tcp_udp_parser.h"

class UDPPacket : public Packet {
public:
	UDPPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
		const eth_header_t& eth, const ip_header_t& ip, const udp_header_t& udp);

	const udp_header_t& udp() const noexcept { return udp_; }

	const char* protocol_name() const noexcept override { return "UDP"; }
	void print(std::ostream& os) const override;

private:
	udp_header_t udp_;
};
