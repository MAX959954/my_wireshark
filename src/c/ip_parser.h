#ifndef IP_PARSER_H
#define IP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IP_ADDR_LEN 4
#define IP_HEADER_MIN_LEN 20

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

typedef struct {
    uint8_t version;
    uint8_t ihl;            /* header length in 32-bit words (5..15) */
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags;          /* top 3 bits of the flags/fragment field */
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_addr[IP_ADDR_LEN];
    uint8_t dst_addr[IP_ADDR_LEN];
    uint8_t checksum_valid; /* 1 if the header checksum is correct, 0 otherwise */
} ip_header_t;

/*
parses a raw IPv4 packet starting at 'data'. On success, fills 'out_header',
points 'out_payload' at the byte right after the (variable-length, options
included) IP header, and 'out_payload_len' at the remaining length, then
returns 0. Returns -1 if 'length' is too short, the version isn't 4, or the
IHL reports a header shorter than IP_HEADER_MIN_LEN or longer than 'length'.
*/
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
