#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* Only the Ethernet/IPv4 case (hw_addr_len=6, proto_addr_len=4) is modeled;
       that covers effectively all ARP traffic seen on real networks. */
#define ARP_HEADER_LEN 28

#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4     0x0800

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

    typedef struct {
        uint16_t hardware_type;
        uint16_t protocol_type;
        uint8_t  hardware_addr_len;
        uint8_t  protocol_addr_len;
        uint16_t opcode;
        uint8_t  sender_mac[6];
        uint8_t  sender_ip[4];
        uint8_t  target_mac[6];
        uint8_t  target_ip[4];
    } arp_header_t;

    int arp_parse(const uint8_t* data, uint32_t length, arp_header_t* out_header);

#ifdef __cplusplus
}
#endif
#endif
