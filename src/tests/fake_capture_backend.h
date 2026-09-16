#ifndef FAKE_CAPTURE_BACKEND_H
#define FAKE_CAPTURE_BACKEND_H

#include <stdint.h>

/*
A second implementation of the capture_backend_t contract declared in
c/capture_backend.h — a "fake NIC" that replays a fixed array of frames
instead of talking to AF_PACKET. It defines the exact same public symbols
as capture_backend_linux.c (capture_backend_get/list_devices/run/
request_stop), so it's a drop-in swap at link time: any test binary that
links this file instead of capture_backend_linux.c exercises the real
capture_backend_run() -> capture_packet_cb -> parser/printer pipeline
without a real network interface or CAP_NET_RAW.
*/

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t* data;
    uint32_t length;
    uint32_t ts_seconds;
    uint32_t ts_microseconds;
} fake_frame_t;

// Installs the frames the next capture_backend_run() call will replay, in
// order, one capture_packet_cb invocation per frame. Not thread-safe -
// this is a single-threaded test double, not a real backend.
void fake_capture_backend_set_frames(const fake_frame_t* frames, int count);

// How many frames the most recent capture_backend_run() actually delivered
// before returning (< the installed count only if request_stop() cut it short).
int fake_capture_backend_delivered_count(void);

#ifdef __cplusplus
}
#endif

#endif
