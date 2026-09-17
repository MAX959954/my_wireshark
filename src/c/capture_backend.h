#ifndef CAPTURE_BACKEND_H
#define CAPTURE_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
Gathers everything that isn't pure capture in one place: writing to a
.pcap file, handling Ctrl+C, reporting an unsupported BPF filter.

Also gives a substitution point for tests - a fake backend can "replay"
packets from an array instead of reading a real NIC.
*/

#define CAPTURE_MAX_DEVICES 32
#define CAPTURE_NAME_LEN 256

typedef struct {
    char name[CAPTURE_NAME_LEN];
    char description[CAPTURE_NAME_LEN]; /* human-readable description (always empty for now) */
} capture_device_t;

typedef void (*capture_packet_cb)(const uint8_t* packet, uint32_t length, uint32_t ts_seconds,
                                  uint32_t ts_microseconds, void* user_data);

/* The interface itself - a vtable. Each field is a function pointer;
   the struct as a whole is a "table of methods" that different backends
   fill in with different implementations - what C++ generates
   automatically for virtual methods, done by hand here. */
typedef struct {
    int (*list_devices)(capture_device_t* output, int max_devices);

    int (*run)(const char* device_name, const char* bpf_filter, const char* pcap_output_path,
               capture_packet_cb cb, void* user_data);

    void (*request_stop)(void);
} capture_backend_t;

const capture_backend_t* capture_backend_get(void);

/* wrappers, so callers don't need to write capture_backend_get()->list_devices() every time */
int capture_backend_list_devices(capture_device_t* output, int max_devices);
int capture_backend_run(const char* device_name, const char* bpf_filter,
                        const char* pcap_output_path, capture_packet_cb cb, void* user_data);
void capture_backend_request_stop(void);

#ifdef __cplusplus
}
#endif

#endif
