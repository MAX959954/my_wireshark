#ifndef DISPFILTER_H
#define DISPFILTER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
A Wireshark-style "display filter" - and deliberately the opposite half
of capfilter.c's "capture filter":

  capture filter (-f, capfilter.c): compiled to classic BPF, run by the
  KERNEL before a frame is ever copied into this process. It only sees
  raw bytes at fixed-ish offsets (that's all BPF can address), so it
  can't ask "is this TCP segment's *parsed* destination port 443" any
  more precisely than "does the byte at this offset equal this value" -
  it decides what you capture at all.

  display filter (-Y, this file): runs entirely in userspace, AFTER
  packet_printer.cpp has already decoded a frame with the real parsers
  (eth_parser.c, ip_parser.c, tcp_udp_parser.c, ...). It matches against
  the parsed FIELDS themselves (tcp.port, ip.src, ...), not byte offsets
  - it decides what you print, out of everything you were handed. The
  packet is fully decoded, checksum-verified, and (with -w) still written
  to the .pcap file regardless of whether the display filter matches.

Supported expression language (a small, Wireshark-flavored subset):

  field     := 'eth.src' | 'eth.dst' | 'eth.addr'
             | 'ip.src' | 'ip.dst' | 'ip.addr'
             | 'ipv6.src' | 'ipv6.dst' | 'ipv6.addr'
             | 'tcp.srcport' | 'tcp.dstport' | 'tcp.port'
             | 'udp.srcport' | 'udp.dstport' | 'udp.port'
  primitive := field ('=='|'!=') value
  expr      := or_expr
  or_expr   := and_expr (('or'|'||') and_expr)*
  and_expr  := not_expr (('and'|'&&') not_expr)*
  not_expr  := ('not'|'!') not_expr | '(' expr ')' | primitive

e.g. `tcp.port == 443`, `ip.src == 10.0.0.1 and not udp.port == 53`,
`ipv6.addr == 2001:db8::1`.

A field that doesn't apply to a given packet (tcp.port on a UDP-only
packet, ip.src on an IPv6 one) simply evaluates to false rather than an
error - the same "absent field -> no match" rule real Wireshark's display
filter engine uses.
*/

typedef struct dispfilter dispfilter_t;

/*
Compiles 'expr' into a filter. NULL or an empty expression compiles to a
filter that matches every packet (the returned pointer is still non-NULL
- free it with dispfilter_free like any other). On a syntax error returns
NULL and writes a human-readable reason into 'err' (a buffer of 'err_len'
bytes; may be NULL if err_len == 0).
*/
dispfilter_t* dispfilter_compile(const char* expr, char* err, int err_len);

/* Frees a filter returned by dispfilter_compile. Safe on NULL. */
void dispfilter_free(dispfilter_t* filter);

/*
One packet's worth of already-parsed fields to match a compiled filter
against - filled in by the caller (packet_printer.cpp) from whichever
headers it actually managed to parse. A 'has_*' flag being 0 means "this
packet doesn't carry this layer", which every comparison against that
layer's fields evaluates to false against (rather than being an error).
*/
typedef struct {
    uint8_t eth_src[6];
    uint8_t eth_dst[6];

    uint8_t has_ip;
    uint8_t ip_src[4];
    uint8_t ip_dst[4];

    uint8_t has_ipv6;
    uint8_t ipv6_src[16];
    uint8_t ipv6_dst[16];

    uint8_t has_tcp;
    uint16_t tcp_src_port;
    uint16_t tcp_dst_port;

    uint8_t has_udp;
    uint16_t udp_src_port;
    uint16_t udp_dst_port;
} dispfilter_fields_t;

/* Evaluates the compiled filter against one packet's fields. Returns 1
   (match - print it) or 0 (no match - skip it). A NULL filter, or one
   compiled from an empty expression, always returns 1. */
int dispfilter_matches(const dispfilter_t* filter, const dispfilter_fields_t* fields);

#ifdef __cplusplus
}
#endif

#endif
