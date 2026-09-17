#ifndef IP_PARSER_H
#define IP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
eth_parser's payload pointer now points at the first byte of the IP
header. This is the second layer of parsing: it extracts the source/
destination hosts, TTL, and which L4 protocol is carried (TCP? UDP?
ICMP?), and tells the next parser where its own header begins. Without
it, only the MAC addresses (which NIC put the frame on the wire) would be
known - not which host is talking to which.
*/

#define IP_ADDR_LEN 4        /* IPv4 address = 4 bytes */
#define IP_HEADER_MIN_LEN 20 /* minimum header, no options */

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

typedef struct {
    uint8_t version;               /* 4 for IPv4 */
    uint8_t ihl;                   /* header length in 32-bit words (5..15) */
    uint8_t tos;                   /* Type of Service */
    uint16_t total_length;         /* whole packet (header + data), bytes */
    uint16_t identification;       /* fragment reassembly ID */
    uint8_t flags;                 /* top 3 bits of the flags/fragment field */
    uint16_t fragment_offset;      /* this fragment's offset */
    uint8_t ttl;                   /* Time To Live - hops remaining */
    uint8_t protocol;              /* 6=TCP, 17=UDP, 1=ICMP */
    uint16_t checksum;             /* header checksum as seen on the wire */
    uint8_t src_addr[IP_ADDR_LEN]; /* source IP */
    uint8_t dst_addr[IP_ADDR_LEN]; /* destination IP */
    uint8_t checksum_valid;        /* 1 if the header checksum is correct, 0 otherwise */
} ip_header_t;

int ip_parse(const uint8_t* data, uint32_t length, ip_header_t* out_header,
             const uint8_t** out_payload, uint32_t* out_payload_len);

/*
formats an IPv4 address as "a.b.c.d" into 'output', which must be at least
IP_ADDR_STR_LEN bytes long.
*/
#define IP_ADDR_STR_LEN 16
void ip_addr_to_str(const uint8_t addr[IP_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
