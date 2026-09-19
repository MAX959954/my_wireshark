#ifndef ICMP_PARSER_H
#define ICMP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
ICMP (RFC 792 for IPv4, RFC 4443 "ICMPv6" for IPv6) is how the network
layer itself reports problems and runs diagnostics - "host unreachable",
"TTL exceeded", and the echo request/reply pair `ping` is built on. It
rides directly inside IPv4 (protocol 1) or IPv6 (next header 58), with no
port numbers of its own: a "connection" here is just a request/reply pair
matched up by (identifier, sequence number).

Both versions share the same first 8 bytes - type(1) code(1) checksum(2)
then a 4-byte "rest of header" that, for echo request/reply, holds a
16-bit identifier and a 16-bit sequence number - which is why one parser
below (icmp_parse) handles both, taking an icmp_family_t to know which
version's type numbers to interpret the message as.

Checksums differ, though: ICMPv4's checksum (RFC 792) is a plain Internet
checksum over the whole ICMP message, no pseudo-header - unlike TCP/UDP,
which is why icmp_parser.c calls checksum_verify() directly for it.
ICMPv6 (RFC 4443 SS2.3) instead reuses the same IPv6 pseudo-header TCP/UDP
use (see checksum.h), with next_header=58 (IP_PROTO_ICMPV6 below).
*/

#define ICMP_HEADER_LEN 8 /* type(1) code(1) checksum(2) + 4-byte rest-of-header */

/* IPv6 next-header value for ICMPv6 (RFC 4443). Lives here rather than in
   ipv6_parser.h because it names an upper-layer protocol carried inside
   IPv6, not anything about IPv6 itself - the same reasoning IP_PROTO_TCP/
   UDP/ICMP follow by living in ip_parser.h rather than eth_parser.h. */
#define IP_PROTO_ICMPV6 58

/* ICMPv4 (RFC 792) type numbers this analyzer recognizes by name. */
#define ICMPV4_TYPE_ECHO_REPLY 0
#define ICMPV4_TYPE_DEST_UNREACHABLE 3
#define ICMPV4_TYPE_ECHO_REQUEST 8
#define ICMPV4_TYPE_TIME_EXCEEDED 11

/* ICMPv6 (RFC 4443) type numbers this analyzer recognizes by name. */
#define ICMPV6_TYPE_DEST_UNREACHABLE 1
#define ICMPV6_TYPE_PACKET_TOO_BIG 2
#define ICMPV6_TYPE_TIME_EXCEEDED 3
#define ICMPV6_TYPE_ECHO_REQUEST 128
#define ICMPV6_TYPE_ECHO_REPLY 129

typedef enum {
    ICMP_FAMILY_V4,
    ICMP_FAMILY_V6,
} icmp_family_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t checksum_valid; /* filled in by icmpv4/6_verify_checksum(), not icmp_parse() */
    uint8_t is_echo;        /* 1 if 'type' is an echo request/reply for the given family */
    uint16_t echo_id;       /* valid only if is_echo */
    uint16_t echo_seq;      /* valid only if is_echo */
} icmp_header_t;

/*
Parses the 8-byte ICMP/ICMPv6 header at 'data'. 'family' picks which
version's type numbers decide whether the message is an echo request/
reply (so echo_id/echo_seq get filled in) - the wire layout itself is
identical either way. Returns 0/-1 ('length' too short for a full header).
*/
int icmp_parse(const uint8_t* data, uint32_t length, icmp_family_t family,
               icmp_header_t* out_header);

/* ICMPv4: a plain Internet checksum over the whole message, no
   pseudo-header (RFC 792). */
int icmpv4_verify_checksum(const uint8_t* segment, uint32_t segment_len);

/* ICMPv6: over the IPv6 pseudo-header with next_header=IP_PROTO_ICMPV6
   (RFC 4443 SS2.3) - mandatory, unlike ICMPv4's checksum having no
   pseudo-header at all. */
int icmpv6_verify_checksum(const uint8_t* segment, uint32_t segment_len, const uint8_t src_ip[16],
                           const uint8_t dst_ip[16]);

#ifdef __cplusplus
}
#endif

#endif
