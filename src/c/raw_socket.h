#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAW_SOCKET_MAX_DEVICES 32
#define RAW_SOCKET_NAME_LEN 256
#define RAW_SOCKET_MAX_FRAME 65536

typedef struct {
    char name[RAW_SOCKET_NAME_LEN];
} raw_socket_device_t;

/*
enumerates network interfaces via getifaddrs(), de-duplicated by name.
Returns the number of entries written into 'output' (<= max_device), or -1
on error. Does not require administrator privileges.
*/
int raw_socket_list_devices(raw_socket_device_t* output, int max_devices);

typedef struct raw_socket_ctx raw_socket_ctx_t;

/*
opens an AF_PACKET/SOCK_RAW/ETH_P_ALL socket bound to 'device_name' via
SO_BINDTODEVICE, and enables promiscuous mode where possible. Requires
CAP_NET_RAW (root or setcap). Returns NULL on error (with a message via
perror).
*/
raw_socket_ctx_t* raw_socket_open(const char* device_name);

/*
blocking receive of one full Ethernet frame (including the 14-byte L2
header) into 'buf'. Returns >0 - the number of bytes received (and fills
'out_ts_seconds'/'out_ts_microseconds'), 0 - a stop was requested (clean
shutdown), -1 - error (errno is set, perror already called).
*/
int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len,
    uint32_t* out_ts_seconds, uint32_t* out_ts_microseconds);

/*
thread-safe (atomic). Calling from any thread makes a blocking
raw_socket_recv() on this 'ctx' return 0 within ~200ms.
*/
void raw_socket_request_stop(raw_socket_ctx_t* ctx);

void raw_socket_close(raw_socket_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
