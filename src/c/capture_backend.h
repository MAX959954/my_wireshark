#ifndef CAPTURE_BACKEND_H
#define CAPTURE_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAPTURE_MAX_DEVICES 32
#define CAPTURE_NAME_LEN    256

typedef struct {
    char name[CAPTURE_NAME_LEN];
    char description[CAPTURE_NAME_LEN];
} capture_device_t;

typedef void (*capture_packet_cb)(const uint8_t* packet, uint32_t length,
    uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data);

/*
Vtable for a capture implementation. main.cpp only talks to this interface
(via capture_backend_get() or the wrapper functions below), so it never has
to know which OS capture API is doing the work underneath - today that's
capture_backend_linux.c on top of raw_socket.c, but a different backend
(e.g. a test/mock one) could be swapped in without touching main.cpp.
*/
typedef struct {
    /* enumerates capture-capable devices into 'output' (<= max_devices).
       Returns the count written, or -1 on error. */
    int (*list_devices)(capture_device_t* output, int max_devices);

    /* opens 'device_name' and blocks the calling thread invoking 'cb' for
       every captured packet until an error occurs or a stop is requested.
       pcap_output_path: NULL/"" to skip, otherwise every captured packet is
       also written to this file in pcap format (openable in Wireshark).
       Returns 0 on clean stop, -1 on error. */
    int (*run)(const char* device_name, const char* bpf_filter,
        const char* pcap_output_path, capture_packet_cb cb, void* user_data);

    /* requests the active run() call to stop; safe to call from a signal
       handler or another thread. No-op if nothing is running. */
    void (*request_stop)(void);
} capture_backend_t;

/* Returns the active backend. Never NULL. */
const capture_backend_t* capture_backend_get(void);

/* convenience wrappers around capture_backend_get()->list_devices/run/request_stop */
int capture_backend_list_devices(capture_device_t* output, int max_devices);
int capture_backend_run(const char* device_name, const char* bpf_filter,
    const char* pcap_output_path, capture_packet_cb cb, void* user_data);
void capture_backend_request_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* CAPTURE_BACKEND_H */
