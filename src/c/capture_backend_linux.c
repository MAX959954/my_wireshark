/*
Linux capture backend: implements the capture_backend_t interface on top of
raw_socket.c (AF_PACKET raw sockets). This is currently the only backend, but
main.cpp reaches it only through capture_backend.h, so it never depends on
raw_socket.h directly.
*/
#include "capture_backend.h"
#include "raw_socket.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

/* pcap file format (see https://wiki.wireshark.org/Development/LibpcapFileFormat).
   Written by hand here instead of linking libpcap, since raw_socket.c already
   avoids that dependency. */
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_record_header_t;

#define PCAP_MAGIC_MICROSECONDS 0xa1b2c3d4u
#define PCAP_LINKTYPE_ETHERNET  1u

/* ctx of the run() call currently blocked below, or NULL when nothing is
   running; only ever read by the SIGINT handler / request_stop(), so a plain
   volatile pointer is enough - there's no concurrent writer. */
static raw_socket_ctx_t* volatile g_active_ctx = NULL;

static void request_stop_impl(void) {
    raw_socket_ctx_t* ctx = g_active_ctx;
    if (ctx != NULL) {
        raw_socket_request_stop(ctx);
    }
}

static void on_sigint(int signum) {
    (void)signum;
    request_stop_impl();
}

static int list_devices_impl(capture_device_t* output, int max_devices) {
    if (max_devices > CAPTURE_MAX_DEVICES) {
        max_devices = CAPTURE_MAX_DEVICES;
    }

    raw_socket_device_t raw_devices[CAPTURE_MAX_DEVICES];
    int count = raw_socket_list_devices(raw_devices, max_devices);
    if (count < 0) {
        return -1;
    }

    for (int i = 0; i < count; i++) {
        strncpy(output[i].name, raw_devices[i].name, CAPTURE_NAME_LEN - 1);
        output[i].name[CAPTURE_NAME_LEN - 1] = '\0';
        /* getifaddrs() (used by raw_socket_list_devices) doesn't carry a
           human-readable description the way pcap_findalldevs() did. */
        output[i].description[0] = '\0';
    }
    return count;
}

static int write_pcap_global_header(FILE* f) {
    pcap_global_header_t hdr;
    hdr.magic_number = PCAP_MAGIC_MICROSECONDS;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = RAW_SOCKET_MAX_FRAME;
    hdr.network = PCAP_LINKTYPE_ETHERNET;
    return fwrite(&hdr, sizeof(hdr), 1, f) == 1 ? 0 : -1;
}

static int write_pcap_record(FILE* f, const uint8_t* data, uint32_t len,
    uint32_t ts_seconds, uint32_t ts_microseconds) {
    pcap_record_header_t rec;
    rec.ts_sec = ts_seconds;
    rec.ts_usec = ts_microseconds;
    rec.incl_len = len;
    rec.orig_len = len;
    if (fwrite(&rec, sizeof(rec), 1, f) != 1) {
        return -1;
    }
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        return -1;
    }
    return 0;
}

static int run_impl(const char* device_name, const char* bpf_filter,
    const char* pcap_output_path, capture_packet_cb cb, void* user_data) {

    if (bpf_filter != NULL && bpf_filter[0] != 0) {
        fprintf(stderr, "warning: BPF filtering is not supported by the "
            "raw-socket backend; capturing all traffic on %s\n", device_name);
    }

    raw_socket_ctx_t* ctx = raw_socket_open(device_name);
    if (ctx == NULL) {
        return -1;
    }

    FILE* pcap_file = NULL;
    if (pcap_output_path != NULL && pcap_output_path[0] != 0) {
        pcap_file = fopen(pcap_output_path, "wb");
        if (pcap_file == NULL) {
            perror("fopen");
            raw_socket_close(ctx);
            return -1;
        }
        if (write_pcap_global_header(pcap_file) != 0) {
            perror("fwrite");
            fclose(pcap_file);
            raw_socket_close(ctx);
            return -1;
        }
    }

    g_active_ctx = ctx;
    void (*previous_sigint_handler)(int) = signal(SIGINT, on_sigint);

    static uint8_t buf[RAW_SOCKET_MAX_FRAME];
    int result = 0;
    for (;;) {
        uint32_t ts_seconds = 0;
        uint32_t ts_microseconds = 0;
        int n = raw_socket_recv(ctx, buf, sizeof(buf), &ts_seconds, &ts_microseconds);
        if (n == 0) {
            break; /* stop requested: clean shutdown */
        }
        if (n < 0) {
            result = -1;
            break;
        }

        if (pcap_file != NULL && write_pcap_record(pcap_file, buf, (uint32_t)n,
            ts_seconds, ts_microseconds) != 0) {
            perror("fwrite");
            result = -1;
            break;
        }

        cb(buf, (uint32_t)n, ts_seconds, ts_microseconds, user_data);
    }

    signal(SIGINT, previous_sigint_handler);
    g_active_ctx = NULL;

    if (pcap_file != NULL) {
        fclose(pcap_file);
    }
    raw_socket_close(ctx);
    return result;
}

static const capture_backend_t g_linux_backend = {
    .list_devices = list_devices_impl,
    .run = run_impl,
    .request_stop = request_stop_impl,
};

const capture_backend_t* capture_backend_get(void) {
    return &g_linux_backend;
}

int capture_backend_list_devices(capture_device_t* output, int max_devices) {
    return capture_backend_get()->list_devices(output, max_devices);
}

int capture_backend_run(const char* device_name, const char* bpf_filter,
    const char* pcap_output_path, capture_packet_cb cb, void* user_data) {
    return capture_backend_get()->run(device_name, bpf_filter, pcap_output_path, cb, user_data);
}

void capture_backend_request_stop(void) {
    capture_backend_get()->request_stop();
}
