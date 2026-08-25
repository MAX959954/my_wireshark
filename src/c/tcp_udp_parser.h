#ifndef TCP_UDP_PARSER_H
#define TCP_UDP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TCP_HEADER_MIN_LEN 20
#define UDP_HEADER_LEN 8

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint8_t checksum_valid; /* filled in by tcp_verify_checksum(), not tcp_parse() */
} tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t checksum_present; /* 0 if checksum == 0 - sender chose not to compute it (RFC 768) */
    uint8_t checksum_valid;   /* filled in by udp_verify_checksum(), not udp_parse() */
} udp_header_t;

/*
parses a raw TCP segment starting at 'data'. On success, fills 'out_header',
points 'out_payload' at the byte right after the (variable-length) TCP
header, and 'out_payload_len' at the remaining length, then returns 0.
Returns -1 if 'length' is too short or the header reports an invalid
data offset.
*/
int tcp_parse(const uint8_t* data, uint32_t length, tcp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
parses a raw UDP segment starting at 'data'. On success, fills 'out_header',
points 'out_payload' at the byte right after the 8-byte header, and
'out_payload_len' at the remaining length, then returns 0. Returns -1 if
'length' is less than UDP_HEADER_LEN.
*/
int udp_parse(const uint8_t* data, uint32_t length, udp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
verifies the checksum of a TCP segment (header + payload) 'segment' of
length 'segment_len', accounting for the IPv4 pseudo-header built from
'src_ip' and 'dst_ip'. Returns 1 if the checksum is correct, 0 otherwise.
*/
int tcp_verify_checksum(const uint8_t* segment, uint32_t segment_len,
    const uint8_t src_ip[4], const uint8_t dst_ip[4]);

/*
verifies the checksum of a UDP segment the same way as tcp_verify_checksum().
If the checksum field inside 'segment' is 0 (valid for UDP/IPv4 per RFC 768 -
the sender chose not to compute it), returns 1 since there's nothing to
verify; to tell this case apart from an actually-matching checksum, see
udp_header_t.checksum_present, filled in by udp_parse().
*/
int udp_verify_checksum(const uint8_t* segment, uint32_t segment_len,
    const uint8_t src_ip[4], const uint8_t dst_ip[4]);

#ifdef __cplusplus
}
#endif

#endif
