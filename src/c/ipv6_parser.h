#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPV6_ADDR_LEN    16
#define IPV6_HEADER_LEN  40

    typedef struct {
        uint8_t  version;        /* always 6 */
        uint8_t  traffic_class;
        uint32_t flow_label;     /* low 20 bits significant */
        uint16_t payload_length;
        uint8_t  next_header;
        uint8_t  hop_limit;
        uint8_t  src_addr[IPV6_ADDR_LEN];
        uint8_t  dst_addr[IPV6_ADDR_LEN];
    } ipv6_header_t;
     
    /*
    parses a raw IPv6 packet starting at 'data'. On success, fills 'out_header',
    points 'out_payload' at the byte right after the (fixed-size,
    IPV6_HEADER_LEN) IPv6 header, and 'out_payload_len' at the remaining
    length, then returns 0. Returns -1 if 'length' is shorter than
    IPV6_HEADER_LEN or the version isn't 6.
    */
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
