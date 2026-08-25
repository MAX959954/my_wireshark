#include "raw_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct raw_socket_ctx {
    int fd;
    atomic_int stop_requested;
}; 

int raw_socket_list_devices(raw_socket_device_t* output, int max_devices) {
    if (output == NULL || max_devices == 0) {
        return -1;
    }

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

        int duplicate = 0;
        for (int j = 0; j < count; j++) {
            if (strcmp(output[j].name, i->ifa_name) == 0){
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

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        perror("socket(AF_PACKET, SOCK_RAW)");
        return NULL;
    }

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

    if (!(ifr.ifr_flags & IFF_PROMISC)) {
        ifr.ifr_flags |= IFF_PROMISC;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
            perror("ioctl(SIOCSIFFLAGS) - promiscuous mode unavailable");
        }
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000; /* 200ms, chtoby raw_socket_recv zametil stop_requested */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(fd);
        return NULL;
    }

    raw_socket_ctx_t* ctx = malloc(sizeof(raw_socket_ctx_t));
    if (ctx == NULL) {
        perror("malloc");
        close(fd);
        return NULL;
    }

    ctx->fd = fd;
    atomic_init(&ctx->stop_requested, 0);
    return ctx;
}

int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len,
    uint32_t  * out_ts_seconds , uint32_t  * out_ts_microseconds ) {

    if (ctx == NULL || buf == NULL) {
        return -1;
    }

    for (;;) {
        if (atomic_load(&ctx->stop_requested)) {
            return 0;
        }
        ssize_t n = recv(ctx->fd, buf, buf_len, 0);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            perror("recv");
            return -1;
        }

        struct timeval tv;
        if (ioctl(ctx->fd, SIOCGSTAMP, &tv) == -1) {
            gettimeofday(&tv, NULL);
        }

        if (out_ts_seconds != NULL) {
            *out_ts_seconds = (uint32_t)tv.tv_sec;
        }

        if (out_ts_microseconds != NULL) {
            *out_ts_microseconds = (uint32_t)tv.tv_usec;
        }

        return (int)n;
    };
}

void raw_socket_request_stop(raw_socket_ctx_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    atomic_store(&ctx->stop_requested, 1);
}

void  raw_socket_close(raw_socket_ctx_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    close(ctx->fd);
    free(ctx);
}


