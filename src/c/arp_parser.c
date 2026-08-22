#include  "arp_parser.h"
#include <stddef.h>
#include <string.h>

int arp_parse(const uint16_t* data, uint32_t length, arp_header_t* out_header) {
	if (data == NULL || out_header == NULL || length < ARP_HEADER_LEN) {
		return -1;
	}

	uint16_t htype = (uint16_t)((data[0]) << 8) | data[1]);
	uint16_t ptype = (uint16_t)(data[2]) << 8 | data[3)];
	uint8_t hlen = data[4];
	uint8_t plen = data[5];

	if (htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen  != 6 || plen != 4) {
		return -1;
	}

	out_header->hardware_type = htype;
	out_header->protocol_type = ptype;
	out_header->hardware_addr_le = hlen;
	out_header->protocol_addr_len = plen;

	out_header->opcode = (uint16_t)((data[6]) << 8) | data[7]);

	memcpy(out_header->sender_mac, data + 8, 6);
	memcpy(out_header->sender_ip, data + 14, 4);
	memcpy(out_header->target_mac, data + 18, 6);
	memcpy(out_header->target_ip, data + 24, 4);
	return  0;
}