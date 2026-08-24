#include "c/capture.h"
#include "c/eth_parser.h"
#include "c/tcp_udp_parser.h"
#include "c/ip_parser.h"
#include "cpp/packet.h"
#include "cpp/tcp_packet.h"
#include "cpp/udp_packet.h"
#include <cstdint>
#include <iostream>

namespace {

	void on_packet(const uint8_t* packet, uint32_t length,
		uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data) {
		auto* count = static_cast<uint64_t*> (user_data);
		++(*count);
		std :: cout << "[#" << *count << "] ";

		eth_header_t eth;
		const uint8_t* eth_payload = nullptr;
		uint32_t eth_playload_len = 0;

		if (eth_parse(packet , length , &eth , &eth_payload , &eth_playload_len) != 0) {
			std::cout << "(truncated Ethernet frame)\n";
			return;
		}

		if (eth.ether_type != ETH_TYPE_IPV4) {
			Packet pkt(ts_seconds, ts_microseconds, length, eth);
			pkt.print(std::cout);
			std::cout << "\n";
			return;
		}

		ip_header_t ip;
		const uint8_t* ip_paylaod = nullptr;
		uint32_t ip_payload_len = 0;
		if (ip_parse(eth_payload , eth_playload_len , &ip , &ip_paylaod , &ip_payload_len) != 0 ) {
			std::cout << "(truncated IPv4 header)\n";
			return;
		}

		switch (ip.protocol) {
			case IP_PROTO_TCP: {
				tcp_header_t tcp;
				if (tcp_parse(ip_paylaod , ip_payload_len , &tcp , nullptr , nullptr )== 0) {
					tcp.checksum_valid = (uint8_t)tcp_verify_checksum(ip_paylaod, ip_payload_len,
						ip.src_addr, ip.dst_addr);
					TCPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, tcp);
					pkt.print(std::cout);
				}
				else {
					Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
					pkt.print(std::cout);
					std::cout << " TCP (truncated)";
				}
				break;
			}
			case IP_PROTO_UDP: {
				udp_header_t udp;
				if (udp_parse(ip_paylaod, ip_payload_len, &udp, nullptr, nullptr) == 0) {
					udp.checksum_valid = (uint8_t)udp_verify_checksum(ip_paylaod, ip_payload_len,
						ip.src_addr, ip.dst_addr);
					UDPPacket pkt(ts_seconds, ts_microseconds, length, eth, ip, udp);
					pkt.print(std::cout);
				}
				else {
					Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
					pkt.print(std::cout);
					std::cout << " UDP (truncated)";
				}
				break;
			}
			default: {
				Packet pkt(ts_seconds, ts_microseconds, length, eth, ip);
				pkt.print(std::cout);
				if (ip.protocol == IP_PROTO_ICMP) {
					std::cout << " ICMP";
				}
				else {
					std::cout << " proto=" << static_cast<int>(ip.protocol);
				}
				break;
			}
		}
		std::cout << "\n";
	}
}

int main() {
	capture_device_t devices[CAPTURE_MAX_DEVICES];
	int device_count = capture_list_device(devices, CAPTURE_MAX_DEVICES);

	if (device_count <= 0) {
		std::cerr << "No capture devices found. Is Npcap installed, and is "
			"this process running as Administrator?\n";
		return 1;
	}

	std::cout << "Available interfaces : \n";
	for (int i = 0; i < device_count; i++) {
		std::cout << "  [" << i << "] " << devices[i].name << " - "
			<< devices[i].description << "\n";
	}

	std::cout << "Select interface index : ";
	int choice = -1;
	std::cin >> choice;

	if (choice < 0 || choice >= device_count) {
		std::cerr << "Invalid choice";
		return 1;
	}

	std::cout << "Capturing on " << devices[choice].name << " (Ctrl+C to stop)...\n";
	uint64_t packet_count = 0;
	if (capture_run(devices[choice].name, on_packet, &packet_count) != 0) {
		std::cerr << "Capturing failed\n";
		return 1;
	}
}
