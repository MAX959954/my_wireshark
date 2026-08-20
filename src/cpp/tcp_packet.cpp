#include "tcp_packet.h"

namespace {
	void print_flags(uint8_t  flags , std :: ofstream & os) {
		if (flags & TCP_FLAG_SYN) os << "SYN";
		if (flags & TCP_FLAG_FIN) os << "FIN";
		if (flags & TCP_FLAG_PSH) os << "PSH";
		if (flags & TCP_FLAG_RST) os << "RST";
		if (flags & TCP_FLAG_URG) os << "URG";
		if (flags & TCP_FLAG_ACK) os << "ACK";
	}
}

TCPPacket::TCPPacket(uint32_t ts_seconds, uint32_t ts_microsecods, uint32_t capture_length,
	const eth_header_t& eth, const ip_header_t& ip, const tcp_header_t& tcp):
	Packet (ts_seconds , ts_microsecods , capture_length , eth , ip) , tcp_(tcp)
{
	
}

void TCPPacket::print(std ::ofstream & os)const  {
	Packet::print(os);
	os << " " << tcp_.src_port << " > " << tcp_.dst_port
		<< " seq= " << tcp_.seq_num << " ack = " << tcp_.ack_num
		<< " flags=[";
	print_flags(tcp_.flags, os);
	os << "]"
}