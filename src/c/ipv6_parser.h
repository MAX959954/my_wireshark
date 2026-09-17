#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
IPv6 exists because IPv4's 4-byte address space (~4 billion) ran out.
IPv6 addresses are 16 bytes (2^128), and the header was simplified along
the way.
*/

#define IPV6_ADDR_LEN 16   /* address is 16 bytes */
#define IPV6_HEADER_LEN 40 /* header is always exactly 40 bytes */

typedef struct {
    uint8_t version;         /* always 6 */
    uint8_t traffic_class;   /* priority/QoS, IPv6's analogue of IPv4 TOS */
    uint32_t flow_label;     /* low 20 bits significant */
    uint16_t payload_length; /* length of the data AFTER the header only */
    uint8_t next_header;     /* 6=TCP, 17=UDP, 58=ICMPv6, 0/43/44=ext. header */
    uint8_t hop_limit;       /* IPv6's name for IPv4's TTL */
    uint8_t src_addr[IPV6_ADDR_LEN];
    uint8_t dst_addr[IPV6_ADDR_LEN];
} ipv6_header_t;

int ipv6_parse(const uint8_t* data, uint32_t length, ipv6_header_t* out_header,
               const uint8_t** out_payload, uint32_t* out_payload_len);

/*
formats an IPv6 address in standard "xxxx:xxxx:...:xxxx" notation into
'output', which must be at least IPV6_ADDR_STR_LEN bytes long.
*/
#define IPV6_ADDR_STR_LEN 40
void ipv6_addr_to_str(const uint8_t addr[IPV6_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
