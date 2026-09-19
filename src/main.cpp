#include "c/capture_backend.h"
#include "c/dispfilter.h"
#include "cpp/packet_printer.h"
#include "cpp/packet_queue.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <thread>

namespace {

void print_usage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " [-i <iface>] [-f \"<bpf filter>\"] [-Y \"<display filter>\"] [-w <out.pcap>]\n"
                 "  -i  capture device name (skips the interactive interface prompt)\n"
                 "  -f  capture filter (BPF, kernel-side), e.g. \"tcp port 443\"\n"
                 "  -Y  display filter (parsed-field match, userspace, post-parse), e.g. "
                 "\"tcp.port == 443\"\n"
                 "  -w  write captured packets to this .pcap file\n"
                 "With no -i, falls back to the interactive interface picker.\n";
}

// The capture thread's callback: just copies each frame into the queue as
// fast as possible and returns, so a slow consumer never makes the
// capture thread miss poll() cycles - see packet_queue.h.
void queue_push_callback(const uint8_t* packet, uint32_t length, uint32_t ts_seconds,
                         uint32_t ts_microseconds, void* user_data) {
    static_cast<PacketQueue*>(user_data)->push(packet, length, ts_seconds, ts_microseconds);
}

}  // namespace

int main(int argc, char** argv) {
    std::string cli_iface;
    std::string cli_capture_filter;
    std::string cli_display_filter;
    std::string cli_pcap_path;
    bool have_iface = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            cli_iface = argv[++i];
            have_iface = true;
        } else if (arg == "-f" && i + 1 < argc) {
            cli_capture_filter = argv[++i];
        } else if (arg == "-Y" && i + 1 < argc) {
            cli_display_filter = argv[++i];
        } else if (arg == "-w" && i + 1 < argc) {
            cli_pcap_path = argv[++i];
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    capture_device_t devices[CAPTURE_MAX_DEVICES];
    int device_count = capture_backend_list_devices(devices, CAPTURE_MAX_DEVICES);

    if (device_count <= 0) {
        std::cerr << "No capture devices found. Raw packet capture requires "
                     "CAP_NET_RAW (run as root, or `sudo setcap cap_net_raw+ep <binary>`).\n";
        return 1;
    }

    std::string device_name;
    std::string capture_filter = cli_capture_filter;
    std::string display_filter = cli_display_filter;
    std::string pcap_path = cli_pcap_path;

    if (have_iface) {
        device_name = cli_iface;
    } else {
        std::cout << "Available interfaces : \n";
        for (int i = 0; i < device_count; i++) {
            std::cout << "  [" << i << "] " << devices[i].name << "\n";
        }

        std::cout << "Select interface index : ";
        int choice = -1;
        std::cin >> choice;

        if (choice < 0 || choice >= device_count) {
            std::cerr << "Invalid choice";
            return 1;
        }
        device_name = devices[choice].name;

        std::cout << "Capture filter, BPF (empty = none): ";
        std::cin.ignore();
        std::getline(std::cin, capture_filter);

        std::cout << "Display filter, e.g. tcp.port == 443 (empty = none): ";
        std::getline(std::cin, display_filter);

        std::cout << "Save to .pcap file (empty = don't save): ";
        std::getline(std::cin, pcap_path);
    }

    char filter_err[128];
    dispfilter_t* filter =
        dispfilter_compile(display_filter.c_str(), filter_err, sizeof(filter_err));
    if (filter == nullptr) {
        std::cerr << "error: invalid display filter \"" << display_filter << "\": " << filter_err
                  << "\n";
        return 1;
    }

    std::cout << "Capturing on " << device_name << " (Ctrl+C to stop)...\n";

    // Producer/consumer pipeline: the capture thread runs capture_backend_run()
    // (kernel recv, .pcap write, BPF capture filter - all unchanged) and only
    // ever copies raw frames into 'queue'; this (main) thread pulls them back
    // off and does all of the parsing, checksum verification, display
    // filtering, and printing. See packet_queue.h for why they're split.
    PacketQueue queue;
    PacketPrinterContext ctx(std::cout);
    ctx.filter = filter;

    int capture_result = 0;
    std::thread capture_thread([&]() {
        capture_result = capture_backend_run(device_name.c_str(), capture_filter.c_str(),
                                             pcap_path.c_str(), queue_push_callback, &queue);
        queue.close();
    });

    CapturedFrame frame;
    while (queue.pop(&frame)) {
        packet_printer_callback(frame.data.data(), static_cast<uint32_t>(frame.data.size()),
                                frame.ts_seconds, frame.ts_microseconds, &ctx);
    }

    capture_thread.join();
    dispfilter_free(filter);

    if (capture_result != 0) {
        std::cerr << "Capturing failed\n";
        return 1;
    }
}
