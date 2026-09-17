#ifndef BPF_INTERP_H
#define BPF_INTERP_H

#include <linux/filter.h>
#include <stdint.h>

/*
A tiny classic-BPF interpreter, for tests only.

Why this exists instead of just SO_ATTACH_FILTER on a real socket: tests
need to run without root/CAP_NET_RAW and without a live network interface
(the asan-ubsan CI job runs ctest with no privileges at all). Interpreting
the bytecode by hand, following the same rules as the kernel (see
Documentation/networking/filter.rst), lets codegen be checked against
synthetic frames fully isolated from the kernel - and doubles as an
independent reading of what capfilter_compile actually generates.

Supports exactly the opcode subset capfilter.c can generate: LD/LDX
(W/H/B, ABS/IND/MSH), ALU AND K, JMP JEQ K, RET K.
*/

/* Returns what the kernel would have returned: 0 = packet dropped, >0 =
   packet accepted (the value is "how many bytes to pass up"; here it's
   enough to know accept vs. reject). */
uint32_t bpf_interp_run(const struct sock_fprog* prog, const uint8_t* pkt, uint32_t pkt_len);

#endif
