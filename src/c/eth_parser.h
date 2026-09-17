#ifndef ETH_PARSER_H
#define ETH_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
A raw socket (AF_PACKET) hands you the whole frame starting at the link
layer, so the first bytes in the buffer are always the Ethernet header.
Every other protocol (IPv4, IPv6, ARP) rides inside an Ethernet frame as
its payload - without stripping this header first, nothing downstream
would know where its own header starts.
*/

#define ETH_ADDR_LEN 6     /* MAC address length in bytes */
#define ETH_HEADER_LEN 14  /* header size without a VLAN tag (6+6+2) */
#define ETH_VLAN_TAG_LEN 4 /* size of an inserted 802.1Q VLAN tag */

/* ether types */
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV6 0x86DD

/* not a real ethertype - marks "a VLAN tag follows" */
#define ETH_TYPE_VLAN 0x8100

typedef struct {
    uint8_t dst_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ether_type; /* the real payload type, with any VLAN tag stripped */
    uint8_t has_vlan;    /* whether a VLAN tag was present (0/1) */
    uint16_t vlan_tci;   /* Tag Control Information, valid only if has_vlan */
} eth_header_t;

/*
VLAN (802.1Q) lets several logically separate networks share one
physical cable by inserting a 4-byte tag into the Ethernet frame:

| TPID (2 bytes) | TCI (2 bytes) |
|    0x8100      |  PCP DEI VID  |

TPID = 0x8100 marks "a VLAN tag is here" (ETH_TYPE_VLAN below). TCI packs
three fields into 16 bits:

 bit:  15 14 13 | 12 | 11 10 9 8 7 6 5 4 3 2 1 0
       PCP      |DEI |        VID (VLAN ID)
       3 bits   | 1  |        12 bits

  PCP (bits 15-13): Priority Code Point - traffic priority (QoS), 0-7
  DEI  (bit 12):    Drop Eligible Indicator - ok to drop under congestion
  VID (bits 11-0):  VLAN ID - which virtual network this frame belongs to
*/

/* VID occupies the low 12 bits; masking with 0x0FFF clears PCP/DEI. */
#define ETH_VLAN_ID(tci) ((tci)&0x0FFF)

/* PCP occupies the top 3 bits; shifting right by 13 drops everything else. */
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
