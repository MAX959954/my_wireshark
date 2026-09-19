#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

/*
The Internet checksum (RFC 1071) - the algorithm used to verify the
integrity of the IPv4 header, a TCP segment, and a UDP datagram. It only
catches accidental bit corruption (line noise, a bad router NIC), not
deliberate tampering. IPv4, TCP, and UDP all use the same algorithm, so
it's implemented once here and shared.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*
accumulates a running sum over 'data'; 'sum' is the previous partial sum
so calls can be chained (e.g. pseudo-header then segment). Does not fold
the carry - that happens once, at the end, in checksum_verify(). An odd
trailing byte is padded with a zero low byte.
*/
uint32_t checksum_partial(const uint8_t* data, uint32_t len, uint32_t sum);

/*
verifies the checksum already present inside 'data' - the checksum field
does not need to be zeroed first. Returns 1 if correct, 0 otherwise.
*/
int checksum_verify(const uint8_t* data, uint32_t len);

/*
Verifies a checksum built over an IPv4 pseudo-header (RFC 793/768's
12-byte src/dst/zero/protocol/length header) followed by 'segment'
itself. Shared by TCP and UDP (tcp_udp_parser.c) - ICMPv4 does NOT use a
pseudo-header at all (RFC 792), so icmp_parser.c calls checksum_verify()
directly instead of this function.
*/
int checksum_verify_ipv4_pseudo(const uint8_t* segment, uint32_t segment_len,
                                const uint8_t src_ip[4], const uint8_t dst_ip[4], uint8_t protocol);

/*
Same idea for IPv6 (RFC 2460 SS8.1): 16-byte source, 16-byte destination,
a 32-bit upper-layer length (not 16-bit - IPv6 jumbograms can in
principle exceed 65535 bytes), 3 zero bytes, then the 1-byte next-header
value. Unlike IPv4, IPv6 makes this pseudo-header mandatory for every
upper-layer protocol that carries a checksum - TCP, UDP, and ICMPv6
(RFC 4443 SS2.3) alike - so tcp_udp_parser.c and icmp_parser.c both call
this one for the IPv6 case.
*/
int checksum_verify_ipv6_pseudo(const uint8_t* segment, uint32_t segment_len,
                                const uint8_t src_ip[16], const uint8_t dst_ip[16],
                                uint8_t next_header);

#ifdef __cplusplus
}
#endif

#endif
