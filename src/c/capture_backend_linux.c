#include "capfilter.h"
#include "capture_backend.h"
#include "raw_socket.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t
        magic_number; /* 0xa1b2c3d4 - marks "this is a pcap file, timestamps in microseconds" */
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;   /* timezone offset from UTC (0 = UTC) */
    uint32_t sigfigs;   /* timestamp accuracy (always 0 in practice) */
    uint32_t snaplen;   /* max stored frame length */
    uint32_t network;   /* link-layer type: 1 = Ethernet */
} pcap_global_header_t; /* 24 bytes, written once at the start of the file */

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;  /* how many bytes of the frame were actually captured */
    uint32_t orig_len;  /* the frame's real length on the wire */
} pcap_record_header_t; /* 16 bytes, written before every packet */

#define PCAP_MAGIC_MICROSECONDS 0xa1b2c3d4u
#define PCAP_LINKTYPE_ETHERNET 1u

/*
Ctrl+C delivers SIGINT, and the handler only gets a signal number - no
ctx, no argc, nothing. Stopping the capture needs a pointer to the active
raw_socket_ctx_t, so it's kept in a file-scope static instead.
*/

/* volatile forbids the compiler from caching this in a register, forcing
   every access to go through memory. */
static raw_socket_ctx_t* volatile g_active_ctx = NULL;

static void request_stop_impl(void) {
    raw_socket_ctx_t* ctx = g_active_ctx;
    if (ctx != NULL) {
        raw_socket_request_stop(ctx); /* async-signal-safe: only does an atomic_store */
    }
}

static void on_sigint(int signum) {
    (void)signum;
    request_stop_impl();
}

/* Pure adapter: calls raw_socket_list_devices and copies
   raw_socket_device_t into capture_device_t. The two layers use distinct
   types on purpose, so capture_backend.h never has to include
   raw_socket.h. */
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

static int write_pcap_record(FILE* f, const uint8_t* data, uint32_t len, uint32_t ts_seconds,
                             uint32_t ts_microseconds) {
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

static int run_impl(const char* device_name, const char* bpf_filter, const char* pcap_output_path,
                    capture_packet_cb cb, void* user_data) {
    struct sock_fprog filter_prog = {0, NULL};
    if (bpf_filter != NULL && bpf_filter[0] != 0) {
        char err[128];
        if (capfilter_compile(bpf_filter, &filter_prog, err, sizeof(err)) != 0) {
            fprintf(stderr, "error: invalid filter expression \"%s\": %s\n", bpf_filter, err);
            return -1;
        }
    }

    raw_socket_ctx_t* ctx = raw_socket_open(device_name);
    if (ctx == NULL) {
        capfilter_free(&filter_prog);
        return -1;
    }

    /* filter_prog.filter == NULL means "accept everything" (see
       capfilter_compile's contract) - skip SO_ATTACH_FILTER entirely
       rather than attaching a pointlessly empty program. */
    if (filter_prog.filter != NULL) {
        if (raw_socket_attach_filter(ctx, &filter_prog) != 0) {
            capfilter_free(&filter_prog);
            raw_socket_close(ctx);
            return -1;
        }
    }
    capfilter_free(&filter_prog); /* setsockopt() already copied it into the kernel */

    FILE* pcap_file = NULL;
    if (pcap_output_path != NULL && pcap_output_path[0] != 0) {
        pcap_file = fopen(pcap_output_path, "wb"); /* "wb": binary mode matters on Windows/WSL */
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

    /*
    The signal handler is installed BEFORE g_active_ctx = ctx. Doing it
    the other way round leaves a window where SIGINT is still caught by
    whatever handler was active before ours (usually terminating the
    process without our cleanup - fclose, clearing promiscuous mode). In
    this order, the worst case is a SIGINT landing in the brief window
    where g_active_ctx is still NULL: request_stop_impl() sees NULL and
    does nothing, which is safe - the user just presses Ctrl+C again.
    */
    void (*previous_sigint_handler)(int) = signal(SIGINT, on_sigint);
    if (previous_sigint_handler == SIG_ERR) {
        /* signal() didn't tell us what the previous handler was, so there's
           nothing to restore - SIG_DFL is the only value safe to install
           unconditionally (unlike SIG_ERR, which isn't a valid handler). */
        perror("signal(SIGINT)");
        previous_sigint_handler = SIG_DFL;
    }
    g_active_ctx = ctx; /* Ctrl+C now knows what to stop */

    /* Static rather than on the stack - 64 KiB would be a lot to risk
       there. One shared buffer is fine as long as run_impl is never
       called from two threads at once (it isn't). */
    static uint8_t buf[RAW_SOCKET_MAX_FRAME];
    int result = 0;
    for (;;) {
        uint32_t ts_seconds = 0;
        uint32_t ts_microseconds = 0;
        int n = raw_socket_recv(ctx, buf, sizeof(buf), &ts_seconds, &ts_microseconds);
        if (n == RAW_SOCKET_STOPPED) {
            break; /* stop requested: clean shutdown */
        }
        if (n < 0) {
            result = -1;
            break;
        }

        if (pcap_file != NULL &&
            write_pcap_record(pcap_file, buf, (uint32_t)n, ts_seconds, ts_microseconds) != 0) {
            perror("fwrite");
            result = -1;
            break;
        }

        /* Write-then-parse order is deliberate: the raw frame lands in
           the .pcap file even if the parser trips over it afterward. */
        cb(buf, (uint32_t)n, ts_seconds, ts_microseconds, user_data);
    }

    signal(SIGINT, previous_sigint_handler);
    g_active_ctx = NULL;

    if (pcap_file != NULL) {
        if (fclose(pcap_file) != 0) {
            /* fclose is the only point where buffered fwrite data actually
               reaches disk - ENOSPC/EIO only surfaces here. */
            perror("fclose");
            result = -1;
        }
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
