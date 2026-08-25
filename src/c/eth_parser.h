#ifndef ETH_PARSER_H
#define ETH_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_ADDR_LEN 6
#define ETH_HEADER_LEN 14
#define ETH_VLAN_TAG_LEN 4

// ether types
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV6 0x86DD
#define ETH_TYPE_VLAN 0x8100

typedef struct {
    uint8_t dst_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ether_type;
    uint8_t has_vlan;
    uint16_t vlan_tci;
} eth_header_t;

#define ETH_VLAN_ID(tci) ((tci) & 0x0FFF)
#define ETH_VLAN_PCP(tci) ((uint8_t)((tci) >> 13))

/*
parses a raw Ethernet II frame starting at 'data'. On success, fills
'out_header', points 'out_payload' at the byte right after the 14-byte
header, and 'out_payload_len' at the remaining length, then returns 0.
Returns -1 if 'length' is too short for a full header.
*/
int eth_parse(const uint8_t* data, uint32_t length, eth_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
formats a MAC address as "xx:xx:xx:xx:xx:xx" into 'output', which must be
at least ETH_MAC_STR_LEN bytes long.
*/
#define ETH_MAC_STR_LEN 18
void eth_mac_to_str(const uint8_t mac[ETH_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
