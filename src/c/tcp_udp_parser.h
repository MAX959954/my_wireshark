#ifndef TCP_UDP_PARSER_H
#define TCP_UDP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
This is L4, the transport layer. ip_parser hands over the host addresses
and the protocol field, which main.cpp uses to call either tcp_parse or
udp_parse. L4's job is to say which process on the host the packet is for
(ports), and, for TCP, what state the connection is in (flags, seq/ack).
*/

#define TCP_HEADER_MIN_LEN 20 /* minimum, without options */
#define UDP_HEADER_LEN 8      /* always 8 */

/*
All 6 flags live in one byte (data[13]), one bit each - checked as
"if (tcp.flags & TCP_FLAG_SYN)". A connection opens with SYN, is answered
with SYN|ACK (0x12), and closes with FIN|ACK.
*/
#define TCP_FLAG_FIN 0x01 /* sender is done sending */
#define TCP_FLAG_SYN 0x02 /* connection start, synchronize seq numbers */
#define TCP_FLAG_RST 0x04 /* reset - no connection / an error */
#define TCP_FLAG_PSH 0x08 /* push data to the application immediately */
#define TCP_FLAG_ACK 0x10 /* ack_num field is meaningful */
#define TCP_FLAG_URG 0x20 /* urgent data present (urgent_pointer) */

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;     /* sequence number of this segment's first byte */
    uint32_t ack_num;     /* "expecting this byte number next" (if ACK is set) */
    uint8_t data_offset;  /* header length in 32-bit words (5..15) */
    uint8_t flags;        /* low 6 bits: URG ACK PSH RST SYN FIN */
    uint16_t window_size; /* flow control: bytes the sender is willing to receive */
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

int tcp_parse(const uint8_t* data, uint32_t length, tcp_header_t* out_header,
              const uint8_t** out_payload, uint32_t* out_payload_len);

int udp_parse(const uint8_t* data, uint32_t length, udp_header_t* out_header,
              const uint8_t** out_payload, uint32_t* out_payload_len);

int tcp_verify_checksum(const uint8_t* segment, uint32_t segment_len, const uint8_t src_ip[4],
                        const uint8_t dst_ip[4]);

int udp_verify_checksum(const uint8_t* segment, uint32_t segment_len, const uint8_t src_ip[4],
                        const uint8_t dst_ip[4]);

/*
Same as tcp_verify_checksum(), but built over the IPv6 pseudo-header
(RFC 2460 section 8.1) instead of the IPv4 one - 16-byte addresses and a
32-bit upper-layer length instead of 4-byte addresses and an 8-bit
protocol byte padded to 16 bits. The protocol number itself (6) doesn't
change between IPv4 and IPv6.
*/
int tcp_verify_checksum_ipv6(const uint8_t* segment, uint32_t segment_len, const uint8_t src_ip[16],
                             const uint8_t dst_ip[16]);

/*
Same idea for UDP, but note the one real difference from udp_verify_checksum():
a zero checksum field is NOT treated as valid here. RFC 2460 section 8.1
makes the UDP checksum mandatory over IPv6 - the IPv4 "sender chose not
to compute one" exemption from RFC 768 doesn't apply, so a zero field is
just a wrong checksum.
*/
int udp_verify_checksum_ipv6(const uint8_t* segment, uint32_t segment_len, const uint8_t src_ip[16],
                             const uint8_t dst_ip[16]);

#ifdef __cplusplus
}
#endif

#endif
