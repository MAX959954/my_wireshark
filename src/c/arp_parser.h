#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <stdint.h>

/*
A host wants to send a packet to 192.168.1.5, but an Ethernet frame is
delivered by MAC address, not IP - and the sender doesn't know the
neighbor's MAC yet. ARP solves this: the host broadcasts "who has
192.168.1.5? tell me your MAC" (a request), the owner replies "that's me,
my MAC is aa:bb:cc:..." (a reply), and the host caches the pair to send
frames straight to that MAC from then on.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* Only the Ethernet/IPv4 case (hw_addr_len=6, proto_addr_len=4) is modeled;
   that covers effectively all ARP traffic seen on real networks. */

#define ARP_HEADER_LEN 28 /* ARP header size for the Ethernet + IPv4 case */

#define ARP_HTYPE_ETHERNET 1 /* hardware type: link-layer technology in use */
/*
  1  Ethernet
  6  IEEE 802 (Token Ring etc.)
 15  Frame Relay
 16  ATM
 20  Serial Line
*/

#define ARP_PTYPE_IPV4 0x0800 /* protocol type: which L3 protocol is being resolved */
/*
  0x0800  IPv4
  0x86DD  IPv6
  0x0806  ARP (itself)
*/

#define ARP_OP_REQUEST 1 /* what kind of message this is */
#define ARP_OP_REPLY 2
/*
  1  request - "who has IP X? tell me your MAC" (usually broadcast)
  2  reply - "IP X is mine, here's my MAC" (unicast back to the requester)
  3  RARP request
  4  RARP reply
*/

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} arp_header_t;

int arp_parse(const uint8_t* data, uint32_t length, arp_header_t* out_header);

#ifdef __cplusplus
}
#endif
#endif
