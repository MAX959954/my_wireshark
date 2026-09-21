#include "fake_capture_backend.h"
#include "c/capture_backend.h"

#include <string.h>

static const fake_frame_t* g_frames = NULL;
static int g_frame_count = 0;
static int g_delivered = 0;
static int g_stop_requested = 0;

void fake_capture_backend_set_frames(const fake_frame_t* frames, int count) {
    g_frames = frames;
    g_frame_count = count;
    g_delivered = 0;
    g_stop_requested = 0;
}

int fake_capture_backend_delivered_count(void) {
    return g_delivered;
}

static int fake_list_devices(capture_device_t* output, int max_devices) {
    if (max_devices <= 0) {
        return 0;
    }
    strncpy(output[0].name, "fake0", CAPTURE_NAME_LEN - 1);
    output[0].name[CAPTURE_NAME_LEN - 1] = '\0';
    output[0].description[0] = '\0';
    return 1;
}

static int fake_run(const char* device_name, const char* bpf_filter, const char* pcap_output_path,
                    capture_packet_cb cb, void* user_data) {
    (void)device_name;
    (void)bpf_filter;
    // Unlike capture_backend_linux.c, the fake backend doesn't write a
    // .pcap file - standing in for the raw NIC is all the "swappable
    // backend" contract requires, not reimplementing every side feature.
    (void)pcap_output_path;

    g_delivered = 0;
    for (int i = 0; i < g_frame_count; i++) {
        if (g_stop_requested) {
            break;
        }
        const fake_frame_t* frame = &g_frames[i];
        cb(frame->data, frame->length, frame->ts_seconds, frame->ts_microseconds, user_data);
        g_delivered++;
    }
    g_stop_requested = 0;
    return 0;
}

static void fake_request_stop(void) {
    g_stop_requested = 1;
}

/* No real kernel/socket behind this backend, so there are no drop counters
   to report - matches capture_backend_t's "-1 if the backend can't report
   stats" contract. */
static int fake_get_last_stats(capture_stats_t* out) {
    (void)out;
    return -1;
}

static const capture_backend_t g_fake_backend = {
    .list_devices = fake_list_devices,
    .run = fake_run,
    .request_stop = fake_request_stop,
    .get_last_stats = fake_get_last_stats,
};

const capture_backend_t* capture_backend_get(void) {
    return &g_fake_backend;
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

int capture_backend_get_last_stats(capture_stats_t* out) {
    return capture_backend_get()->get_last_stats(out);
}
