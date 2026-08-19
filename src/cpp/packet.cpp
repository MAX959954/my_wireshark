#include "packet.h"

#include <iomanip>

Packet::Packet(uint32_t ts_seconds, uint32_t ts_microseconds, uint32_t capture_length,
    const eth_header_t& eth, std::optional<ip_header_t> ip)
    : ts_seconds_(ts_seconds), ts_microseconds_(ts_microseconds),
      capture_length_(capture_length), eth_(eth), ip_(ip) {
}

void Packet::print(std::ostream& os) const {
    char src_mac[ETH_MAC_STR_LEN];
    char dst_mac[ETH_MAC_STR_LEN];
    eth_mac_to_str(eth_.src_mac, src_mac);
    eth_mac_to_str(eth_.dst_mac, dst_mac);

    os << ts_seconds_ << "." << std::setw(6) << std::setfill('0') << ts_microseconds_
       << " len=" << capture_length_
       << " " << src_mac << " > " << dst_mac
       << " [" << protocol_name() << "]";

    if (has_ip()) {
        char src_ip[IP_ADDR_STR_LEN];
        char dst_ip[IP_ADDR_STR_LEN];
        ip_addr_to_str(ip_->src_addr, src_ip);
        ip_addr_to_str(ip_->dst_addr, dst_ip);
        os << " " << src_ip << " > " << dst_ip << " ttl=" << static_cast<int>(ip_->ttl);
    }
}
