#ifndef CAPFILTER_H
#define CAPFILTER_H

#include <linux/filter.h> /* struct sock_fprog / struct sock_filter */

/*
BPF (Berkeley Packet Filter)

A tiny virtual machine inside the Linux kernel. It has an accumulator
register A, a register X, "memory" M[0..15], and a program - an array of
fixed-format 8-byte instructions: { code, jt, jf, k }.

  code  - what to do (load a byte, compare, return a result)
  k     - the operand (an offset into the packet, a comparison constant)
  jt/jf - how many instructions to jump if the condition is true/false

The program is handed to the kernel via setsockopt(SO_ATTACH_FILTER). On
every incoming frame the kernel runs it; it looks at the packet's bytes
and returns a number - how many bytes to pass up (0 = drop the packet).
Filtering happens in the kernel, before the packet is copied into
userspace - that's why "tcp port 443" doesn't route all traffic through
the application.

Supported expression language (a subset of pcap-filter(7)):

  primitive := 'tcp' | 'udp' | 'icmp' | 'ip' | 'ip6' | 'arp'
             | ['src'|'dst'] 'host' A.B.C.D
             | ['src'|'dst'] 'port' NUM
             | ['src'|'dst'] 'net' A.B.C.D '/' PREFIXLEN
  expr      := or_expr
  or_expr   := and_expr (('or'|'||') and_expr)*
  and_expr  := not_expr (('and'|'&&') not_expr)*
  not_expr  := ('not'|'!') not_expr | '(' expr ')' | primitive

Differences from full pcap-filter: 'and'/'or' between primitives are
mandatory (no implicit juxtaposition like "tcp port 80"), and 'host'/
'net' matching only works for IPv4 (matching what this analyzer parses
past Ethernet in the first place - see the README's note on IPv6 L4).

The compiler is a classic three-stage pipeline: lexer (string -> tokens)
-> recursive-descent parser (tokens -> AST) -> codegen (AST -> bytecode)
with backpatching (the classic technique for compiling short-circuit
boolean expressions: each node compiles to code that either falls
through on true or jumps on false, and the actual jump targets are
filled in once it becomes known where they need to point).
*/

#ifdef __cplusplus
extern "C" {
#endif

/*
Compiles 'expr' into *out. On success returns 0 and fills out->filter
(heap-allocated, free with capfilter_free) and out->len. NULL or an empty
expression is not an error: it yields out->len == 0 / out->filter ==
NULL, meaning "pass every packet" - in that case the caller should skip
the SO_ATTACH_FILTER call entirely.

On a syntax error, an unknown primitive, or an overly complex expression,
returns -1 and writes a human-readable reason into 'err' (a buffer of
'err_len' bytes; may be NULL if err_len == 0).
*/
int capfilter_compile(const char* expr, struct sock_fprog* out, char* err, int err_len);

/* Frees out->filter and zeroes the struct. Safe on an empty / NULL
   program. */
void capfilter_free(struct sock_fprog* fprog);

/* For debugging: prints the program one instruction per line to stdout,
   in a format comparable to `tcpdump -dd "<expr>"`. */
void capfilter_print(const struct sock_fprog* fprog);

#ifdef __cplusplus
}
#endif

#endif
