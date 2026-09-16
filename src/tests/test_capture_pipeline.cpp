#include "test_util.h"

#include "c/capture_backend.h"
#include "cpp/packet_printer.h"
#include "fake_capture_backend.h"

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

/*
capture_backend.h's own doc comment says the vtable exists to be swapped
"e.g. for tests" - but until now nothing actually swapped it. This file
links fake_capture_backend.c instead of capture_backend_linux.c/raw_socket.c
and drives the exact same public API (capture_backend_list_devices/run/
request_stop) main.cpp uses, proving the seam works end-to-end:
fake capture -> real parsers -> real C++ print pipeline.
*/

namespace {

    // Ethernet(broadcast) + ARP request: "who-has 10.0.0.2 tell 10.0.0.1"
    const uint8_t FRAME_ARP[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        10, 0, 0, 1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        10, 0, 0, 2,
    };

    // Ethernet + IPv4(10.0.0.1 -> 10.0.0.2, correct header checksum) + TCP SYN
    // (src_port=8080 dst_port=80 seq=1 ack=0, correct segment checksum -
    // same VALID_TCP bytes test_tcp_udp_parser.c already proves are correct
    // for this exact src/dst pair).
    const uint8_t FRAME_TCP[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x66, 0xce,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x1f, 0x90, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x5b, 0xff, 0x00, 0x00,
    };

    // Ethernet + IPv4(10.0.0.1 -> 10.0.0.2, correct header checksum) + UDP
    // (src_port=12345 dst_port=53, correct segment checksum - same
    // VALID_UDP bytes test_tcp_udp_parser.c already proves are correct for
    // this exact src/dst pair).
    const uint8_t FRAME_UDP[] = {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x02, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x66, 0xcb,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0x1d, 0xc8, 0xde, 0xad, 0xbe, 0xef,
    };

    // Shorter than a minimal 14-byte Ethernet header - exercises the
    // "(truncated Ethernet frame)" fallback path.
    const uint8_t FRAME_TRUNCATED[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

    void list_devices_reports_the_fake_device() {
        capture_device_t devices[CAPTURE_MAX_DEVICES];
        int count = capture_backend_list_devices(devices, CAPTURE_MAX_DEVICES);

        TEST_ASSERT(count == 1);
        TEST_ASSERT(std::strcmp(devices[0].name, "fake0") == 0);
    }

    void pipeline_decodes_and_prints_each_frame_kind() {
        const fake_frame_t frames[] = {
            { FRAME_ARP, sizeof(FRAME_ARP), 1000, 1 },
            { FRAME_TCP, sizeof(FRAME_TCP), 2000, 2 },
            { FRAME_UDP, sizeof(FRAME_UDP), 3000, 3 },
            { FRAME_TRUNCATED, sizeof(FRAME_TRUNCATED), 4000, 4 },
        };
        fake_capture_backend_set_frames(frames, 4);

        std::ostringstream out;
        PacketPrinterContext ctx(out);
        int rc = capture_backend_run("fake0", "", "", packet_printer_callback, &ctx);

        TEST_ASSERT(rc == 0);
        TEST_ASSERT(fake_capture_backend_delivered_count() == 4);

        std::string output = out.str();
        TEST_ASSERT(output.find(
            "[#1] 1000.000001 len=42 02:00:00:00:00:01 > ff:ff:ff:ff:ff:ff "
            "[ARP] who-has 10.0.0.2 tell 10.0.0.1") != std::string::npos);
        TEST_ASSERT(output.find(
            "[#2] 2000.000002 len=54 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 "
            "[TCP] 10.0.0.1 > 10.0.0.2 ttl=64 8080 > 80 seq=1 ack=0 flags=[SYN]") != std::string::npos);
        TEST_ASSERT(output.find(
            "[#3] 3000.000003 len=46 de:ad:be:ef:00:02 > de:ad:be:ef:00:01 "
            "[UDP] 10.0.0.1 > 10.0.0.2 ttl=64 12345 > 53 len=12") != std::string::npos);
        TEST_ASSERT(output.find("[#4] (truncated Ethernet frame)") != std::string::npos);

        // Every checksum above was chosen to be correct - none of the
        // well-formed frames should have been flagged as corrupted.
        TEST_ASSERT(output.find("csum=BAD") == std::string::npos);
    }

    void stop_after_first_frame_cb(const uint8_t* packet, uint32_t length,
        uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data) {
        (void)packet;
        (void)length;
        (void)ts_seconds;
        (void)ts_microseconds;
        auto* seen = static_cast<int*>(user_data);
        ++(*seen);
        capture_backend_request_stop(); // same call SIGINT triggers during live capture
    }

    void request_stop_cuts_the_replay_short() {
        const fake_frame_t frames[] = {
            { FRAME_ARP, sizeof(FRAME_ARP), 1000, 1 },
            { FRAME_TCP, sizeof(FRAME_TCP), 2000, 2 },
            { FRAME_UDP, sizeof(FRAME_UDP), 3000, 3 },
        };
        fake_capture_backend_set_frames(frames, 3);

        int seen = 0;
        int rc = capture_backend_run("fake0", "", "", stop_after_first_frame_cb, &seen);

        TEST_ASSERT(rc == 0);
        TEST_ASSERT(seen == 1);
        TEST_ASSERT(fake_capture_backend_delivered_count() == 1);
    }

}

int main(void) {
    TEST_RUN(list_devices_reports_the_fake_device);
    TEST_RUN(pipeline_decodes_and_prints_each_frame_kind);
    TEST_RUN(request_stop_cuts_the_replay_short);
    TEST_MAIN_END();
}
