#include "udp_packet.h"

UDPPacket::UDPPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
	const eth_header_t& eth, const ip_header_t& ip, const udp_header_t& udp)
	: Packet(ts_seconds, ts_microseconds, capture_length, eth, ip), udp_(udp) {
}

void UDPPacket::print(std::ostream& os) const {
	Packet::print(os);
	os << " " << udp_.src_port << " > " << udp_.dst_port
	   << " len=" << udp_.length;
}
