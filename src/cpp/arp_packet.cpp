#include "arp_packet.h"

#include "c/ip_parser.h"

ArpPacket::ArpPacket(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
    const eth_header_t& eth, const arp_header_t& arp)
    : Packet(ts_seconds, ts_microseconds, capture_length, eth), arp_(arp) {
}

void ArpPacket::print(std::ostream& os) const {
    Packet::print(os);

    char sender_ip[IP_ADDR_STR_LEN];
    char target_ip[IP_ADDR_STR_LEN];
    ip_addr_to_str(arp_.sender_ip, sender_ip);
    ip_addr_to_str(arp_.target_ip, target_ip);

    if (arp_.opcode == ARP_OP_REQUEST) {
        os << " who-has " << target_ip << " tell " << sender_ip;
    }
    else if (arp_.opcode == ARP_OP_REPLY) {
        char sender_mac[ETH_MAC_STR_LEN];
        eth_mac_to_str(arp_.sender_mac, sender_mac);
        os << " " << sender_ip << " is-at " << sender_mac;
    }
    else {
        os << " op=" << arp_.opcode;
    }
}
