#include "raw_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/*
PACKET_MMAP / TPACKET_V3 - zero-copy ring buffer capture.

The problem with "one recv() per packet": each call is a user/kernel
transition, and there's one per frame. At any interesting packet rate
(tens to hundreds of thousands of pps), that becomes the bottleneck -
time goes into syscalls and per-frame copies rather than into parsing.

PACKET_MMAP solves this differently: the kernel and the process mmap the
same block of memory - a ring of consecutive "blocks". The kernel fills
it with incoming frames on its own (no syscall involved), and once a
block fills up or tp_retire_blk_tov (our timeout, 200ms) expires, marks
it TP_STATUS_USER and wakes us if we're asleep in poll(). We then drain
as many frames as we like from that block with zero syscalls, and hand it
back to the kernel (TP_STATUS_KERNEL) with a single memory write once
we're done. The copy from the ring into the caller's buffer
(raw_socket_recv's 'buf') still happens, to keep this module's API
unchanged for its callers (capture_backend_linux.c, tests) - but the
"kernel -> socket buffer -> our buffer" copy on EVERY packet is gone;
only the "ring -> buf" copy remains, with zero syscalls as long as the
ring has unread frames.

TPACKET_V3 (rather than V1/V2) is used because frames within a block are
packed back-to-back at variable length (via tp_next_offset) instead of
fixed-size slots - less padding waste, and the kernel decides on its own
when to close a block (full, or timed out) instead of blocking until a
slot frees up.
*/

#define RS_RING_BLOCK_SIZE \
    (1u << 20)                   /* 1 MiB per block; a multiple of the page size and frame_size */
#define RS_RING_BLOCK_NR 8u      /* 8 blocks => 8 MiB ring in total */
#define RS_RING_FRAME_SIZE 2048u /* only used to size tp_frame_nr */
#define RS_RING_RETIRE_TOV_MS                                                              \
    200u /* how long a block waits to fill before closing empty/partial - same granularity \
            SO_RCVTIMEO used to give, so Ctrl+C reacts just as fast */

struct raw_socket_ctx {
    int fd;
    atomic_int stop_requested;
    char device_name[RAW_SOCKET_NAME_LEN]; /* needed to clear promiscuous mode on close */
    int promisc_set_by_us; /* 1 if we're the ones who turned on IFF_PROMISC (and must turn it off)
                            */

    uint8_t* ring;    /* the whole mmap'd ring (all blocks, contiguous) */
    size_t ring_size; /* = block_size * block_nr, needed for munmap */
    unsigned int block_size;
    unsigned int block_nr;

    /* Read cursor: which block we're reading and how many of its packets
       we've already handed out. cur_pkt_idx == 0 means "haven't started
       this block yet" - so check its block_status first instead of just
       loading the next packet. */
    unsigned int cur_block;
    unsigned int cur_pkt_idx;
    unsigned int cur_pkt_offset; /* byte offset of the next tpacket3_hdr within the block */
    unsigned int cur_num_pkts;   /* total packets in the current block (cached bh1.num_pkts) */
};

static uint8_t* rs_block_at(raw_socket_ctx_t* ctx, unsigned int index) {
    return ctx->ring + (size_t)index * ctx->block_size;
}

int raw_socket_list_devices(raw_socket_device_t* output, int max_devices) {
    if (output == NULL || max_devices == 0) {
        return -1;
    }

    /* getifaddrs() is a POSIX call returning a linked list of every
       network address on the system; it needs no privileges. */
    struct ifaddrs* addr = NULL;
    if (getifaddrs(&addr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    int count = 0;
    for (struct ifaddrs* i = addr; i != NULL && count < max_devices; i = i->ifa_next) {
        if (i->ifa_name == NULL) {
            continue;
        }

        /* getifaddrs returns one entry per address, not per interface -
           eth0 can have an IPv4 address, an IPv6 address, and a MAC, each
           a separate entry named "eth0". Hence the dedup below. */
        int duplicate = 0;
        for (int j = 0; j < count; j++) {
            if (strcmp(output[j].name, i->ifa_name) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        strncpy(output[count].name, i->ifa_name, RAW_SOCKET_NAME_LEN - 1);
        output[count].name[RAW_SOCKET_NAME_LEN - 1] = '\0';
        count++;
    }

    freeifaddrs(addr);
    return count;
}

raw_socket_ctx_t* raw_socket_open(const char* device_name) {
    if (device_name == NULL) {
        return NULL;
    }

    /* htons (host-to-network short): the third argument must be in
       network byte order. ETH_P_ALL = 0x0003; without htons, a
       little-endian machine would send the kernel 0x0300 instead. */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        perror("socket(AF_PACKET, SOCK_RAW)");
        return NULL;
    }

    /* Bind to a single interface - without this the socket would receive
       traffic from every interface at once. +1 includes the trailing
       '\0' in the length. */
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device_name,
                   (socklen_t)(strlen(device_name) + 1)) == -1) {
        perror("setsockopt(SO_BINDTODEVICE)");
        close(fd);
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("ioctl(SIOCGIFFLAGS)");
        close(fd);
        return NULL;
    }

    /* Promiscuous mode: normally a NIC drops frames not addressed to its
       own MAC (or broadcast/multicast). In promiscuous mode it hands the
       kernel everything it physically hears on the segment, including
       other hosts' traffic - essential for a sniffer. */
    int promisc_set_by_us = 0;
    if (!(ifr.ifr_flags & IFF_PROMISC)) {
        ifr.ifr_flags |= IFF_PROMISC;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
            perror("ioctl(SIOCSIFFLAGS) - promiscuous mode unavailable");
        } else {
            promisc_set_by_us = 1; /* we turned it on, so we're responsible for turning it off */
        }
    }

    /* Switch the socket from "plain" AF_PACKET to ring-buffer mode - see
       the PACKET_MMAP comment above. */
    int tpacket_version = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &tpacket_version, sizeof(tpacket_version)) ==
        -1) {
        perror("setsockopt(PACKET_VERSION, TPACKET_V3)");
        close(fd);
        return NULL;
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = RS_RING_BLOCK_SIZE;
    req.tp_frame_size = RS_RING_FRAME_SIZE;
    req.tp_block_nr = RS_RING_BLOCK_NR;
    req.tp_frame_nr = (RS_RING_BLOCK_SIZE / RS_RING_FRAME_SIZE) * RS_RING_BLOCK_NR;
    req.tp_retire_blk_tov = RS_RING_RETIRE_TOV_MS;

    /* Ask the kernel to allocate and lay out the ring for this socket.
       After this call, frames are already flowing into the ring. */
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) == -1) {
        perror("setsockopt(PACKET_RX_RING)");
        close(fd);
        return NULL;
    }

    size_t ring_size = (size_t)req.tp_block_size * req.tp_block_nr;
    void* ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        perror("mmap(PACKET_RX_RING)");
        close(fd);
        return NULL;
    }

    raw_socket_ctx_t* ctx = malloc(sizeof(raw_socket_ctx_t));
    if (ctx == NULL) {
        perror("malloc");
        munmap(ring, ring_size);
        close(fd);
        return NULL;
    }

    ctx->fd = fd;
    atomic_init(&ctx->stop_requested, 0);
    strncpy(ctx->device_name, device_name, RAW_SOCKET_NAME_LEN - 1);
    ctx->device_name[RAW_SOCKET_NAME_LEN - 1] = '\0';
    ctx->promisc_set_by_us = promisc_set_by_us;
    ctx->ring = ring;
    ctx->ring_size = ring_size;
    ctx->block_size = req.tp_block_size;
    ctx->block_nr = req.tp_block_nr;
    ctx->cur_block = 0;
    ctx->cur_pkt_idx = 0;
    ctx->cur_pkt_offset = 0;
    ctx->cur_num_pkts = 0;
    return ctx;
}

int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len, uint32_t* out_ts_seconds,
                    uint32_t* out_ts_microseconds) {
    if (ctx == NULL || buf == NULL) {
        return -1;
    }

    for (;;) {
        if (atomic_load(&ctx->stop_requested)) {
            return RAW_SOCKET_STOPPED; /* distinct code - not to be confused with a valid
                                          zero-length frame */
        }

        struct tpacket_block_desc* bd =
            (struct tpacket_block_desc*)rs_block_at(ctx, ctx->cur_block);

        if (ctx->cur_pkt_idx == 0) {
            /* Haven't started reading this block yet - first confirm it
               actually belongs to us (TP_STATUS_USER) rather than still
               being filled by the kernel. */
            if (!(bd->hdr.bh1.block_status & TP_STATUS_USER)) {
                /* poll() replaces the old recv()-timeout: sleep until the
                   kernel either closes the current block (full, or via
                   tp_retire_blk_tov) or our own timeout expires, then loop
                   back up to re-check stop_requested - the same role the
                   old 200ms EAGAIN used to play. */
                struct pollfd pfd;
                pfd.fd = ctx->fd;
                pfd.events = POLLIN;
                pfd.revents = 0;
                int rc = poll(&pfd, 1, (int)RS_RING_RETIRE_TOV_MS);
                if (rc < 0 && errno != EINTR) {
                    perror("poll");
                    return -1;
                }
                continue;
            }

            ctx->cur_num_pkts = bd->hdr.bh1.num_pkts;
            ctx->cur_pkt_offset = bd->hdr.bh1.offset_to_first_pkt;

            if (ctx->cur_num_pkts == 0) {
                /* Block closed on timeout with no packets at all (idle
                   interface) - hand it back to the kernel and move on. */
                bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
                ctx->cur_block = (ctx->cur_block + 1) % ctx->block_nr;
                continue;
            }
        }

        struct tpacket3_hdr* hdr = (struct tpacket3_hdr*)((uint8_t*)bd + ctx->cur_pkt_offset);
        const uint8_t* frame = (const uint8_t*)hdr + hdr->tp_mac;
        uint32_t frame_len = hdr->tp_snaplen;
        uint32_t copy_len = frame_len < buf_len ? frame_len : buf_len;
        memcpy(buf, frame, copy_len);

        if (out_ts_seconds != NULL) {
            *out_ts_seconds = hdr->tp_sec;
        }
        if (out_ts_microseconds != NULL) {
            /* This timestamp is the kernel/NIC's own, taken when this
               specific frame arrived (per-packet) - more accurate than
               the old ioctl(SIOCGSTAMP), which asked "when did the last
               frame arrive on this socket" after the fact, post-recv(). */
            *out_ts_microseconds = hdr->tp_nsec / 1000;
        }

        ctx->cur_pkt_idx++;
        if (ctx->cur_pkt_idx >= ctx->cur_num_pkts) {
            /* Block fully drained - hand it back to the kernel and move
               to the next one in the ring. */
            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            ctx->cur_block = (ctx->cur_block + 1) % ctx->block_nr;
            ctx->cur_pkt_idx = 0;
        } else {
            ctx->cur_pkt_offset += hdr->tp_next_offset;
        }

        return (int)copy_len;
    }
}

int raw_socket_get_stats(raw_socket_ctx_t* ctx, uint32_t* out_packets, uint32_t* out_drops) {
    if (ctx == NULL || out_packets == NULL || out_drops == NULL) {
        return -1;
    }

    struct tpacket_stats_v3 stats;
    socklen_t len = sizeof(stats);
    if (getsockopt(ctx->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) == -1) {
        perror("getsockopt(PACKET_STATISTICS)");
        return -1;
    }

    *out_packets = stats.tp_packets;
    *out_drops = stats.tp_drops;
    return 0;
}

int raw_socket_attach_filter(raw_socket_ctx_t* ctx, const struct sock_fprog* prog) {
    if (ctx == NULL || prog == NULL) {
        return -1;
    }
    if (setsockopt(ctx->fd, SOL_SOCKET, SO_ATTACH_FILTER, prog, sizeof(*prog)) == -1) {
        perror("setsockopt(SO_ATTACH_FILTER)");
        return -1;
    }
    return 0;
}

void raw_socket_request_stop(raw_socket_ctx_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    atomic_store(&ctx->stop_requested, 1);
}

void raw_socket_close(raw_socket_ctx_t* ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->promisc_set_by_us) {
        /* Symmetric with enabling it: clear the IFF_PROMISC bit we set
           ourselves, otherwise the interface stays promiscuous after the
           program exits. */
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ctx->device_name, IFNAMSIZ - 1);

        if (ioctl(ctx->fd, SIOCGIFFLAGS, &ifr) == -1) {
            perror("ioctl(SIOCGIFFLAGS) - failed to read flags while disabling promiscuous mode");
        } else {
            ifr.ifr_flags &= ~IFF_PROMISC;
            if (ioctl(ctx->fd, SIOCSIFFLAGS, &ifr) == -1) {
                perror("ioctl(SIOCSIFFLAGS) - failed to disable promiscuous mode");
            }
        }
    }

    munmap(ctx->ring, ctx->ring_size);
    close(ctx->fd);
    free(ctx);
}
