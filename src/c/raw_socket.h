#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
The source of data, at the very bottom of the stack (the L1/L2
boundary): it asks the Linux kernel for a copy of every frame that
passes through the NIC, and hands the raw buffer plus a timestamp
upward.

Pipeline: raw_socket -> capture_backend_linux (wraps it, writes .pcap) ->
main.cpp -> parsers.
*/

/*
A normal socket (AF_INET) only gives you the payload of your own
connections - the kernel has already stripped Ethernet/IP/TCP.
socket(AF_PACKET, SOCK_RAW, ETH_P_ALL) is different:

  AF_PACKET - operate at the link layer (L2)
  SOCK_RAW  - hand back the whole frame, including the Ethernet header
  ETH_P_ALL - every protocol, all traffic, not just what's addressed to us

That's exactly what a sniffer needs. It requires CAP_NET_RAW (root, or
setcap cap_net_raw+ep) because it lets you read other hosts' traffic.
*/

#define RAW_SOCKET_MAX_DEVICES 32  /* max interfaces returned by the listing */
#define RAW_SOCKET_NAME_LEN 256    /* max interface name length ("eth0", "wlan0", ...) */
#define RAW_SOCKET_MAX_FRAME 65536 /* max frame size (buffer for one packet) */

typedef struct {
    char name[RAW_SOCKET_NAME_LEN];
} raw_socket_device_t;

int raw_socket_list_devices(raw_socket_device_t* output, int max_devices);

typedef struct raw_socket_ctx raw_socket_ctx_t;

raw_socket_ctx_t* raw_socket_open(const char* device_name);

/* Distinct return code for "a stop was requested", from raw_socket_recv():
   doesn't collide with a frame length (>= 0, 0 is a legitimate zero-length
   frame) or with -1 (error). */
#define RAW_SOCKET_STOPPED (-2)

/* receives one frame (blocking).
   Return value: >= 0 - frame length in bytes (0 is a legitimate zero-length
   frame, not a stop signal); -1 - recv() error; RAW_SOCKET_STOPPED - a stop
   was requested via raw_socket_request_stop(). */
int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len, uint32_t* out_ts_seconds,
                    uint32_t* out_ts_microseconds);

/*
Attaches a compiled BPF program (see capfilter.h) to the socket via
SO_ATTACH_FILTER, so the kernel drops non-matching packets itself before
raw_socket_recv() ever sees them - filtering happens in the kernel, not
in userspace. 'prog' is not retained (setsockopt copies the program into
the kernel), so it can be freed with capfilter_free() right after this
call returns. Returns 0/-1; the struct itself (linux/filter.h) isn't
included here so raw_socket.h doesn't drag BPF details into callers that
don't filter.
*/
struct sock_fprog;
int raw_socket_attach_filter(raw_socket_ctx_t* ctx, const struct sock_fprog* prog);

/*
Reads the kernel's own packet/drop counters for this socket
(SOL_PACKET/PACKET_STATISTICS, struct tpacket_stats_v3 - matching the
TPACKET_V3 ring mode raw_socket_open() puts the socket into). 'tp_drops'
is what makes this worth having: it's incremented by the kernel itself
whenever an incoming frame had nowhere to go because every block in the
ring was still full (userspace too slow to keep up) - the one number that
turns "the capture looked fine" into "the capture kept up with the wire,
verified".

Kernel semantics, not this function's: the counters reset to zero on
every read, so the values written to 'out_packets' and 'out_drops' are
deltas since the last call (or since the socket was opened, on the first
call) - not running totals. Returns 0/-1.
*/
int raw_socket_get_stats(raw_socket_ctx_t* ctx, uint32_t* out_packets, uint32_t* out_drops);

/* asks recv to return (called from another thread or a signal handler) */
void raw_socket_request_stop(raw_socket_ctx_t* ctx);

/* closes the socket and frees the context */
void raw_socket_close(raw_socket_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
