#include "c/capture_backend.h"
#include "cpp/packet_printer.h"
#include <cstdint>
#include <iostream>
#include <string>

namespace {

    void print_usage(const char* argv0) {
        std::cerr << "Usage: " << argv0 << " [-i <iface>] [-f \"<bpf filter>\"] [-w <out.pcap>]\n"
            "  -i  capture device name (skips the interactive interface prompt)\n"
            "  -f  BPF filter, e.g. \"tcp port 443\"\n"
            "  -w  write captured packets to this .pcap file\n"
            "With no -i, falls back to the interactive interface picker.\n";
    }

}

int main(int argc, char** argv) {
    std::string cli_iface;
    std::string cli_filter;
    std::string cli_pcap_path;
    bool have_iface = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            cli_iface = argv[++i];
            have_iface = true;
        }
        else if (arg == "-f" && i + 1 < argc) {
            cli_filter = argv[++i];
        }
        else if (arg == "-w" && i + 1 < argc) {
            cli_pcap_path = argv[++i];
        }
        else {
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
    std::string filter = cli_filter;
    std::string pcap_path = cli_pcap_path;

    if (have_iface) {
        device_name = cli_iface;
    }
    else {
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

        std::cout << "BPF filter (empty = none): ";
        std::cin.ignore();
        std::getline(std::cin, filter);

        std::cout << "Save to .pcap file (empty = don't save): ";
        std::getline(std::cin, pcap_path);
    }

    std::cout << "Capturing on " << device_name << " (Ctrl+C to stop)...\n";
    PacketPrinterContext ctx(std::cout);
    if (capture_backend_run(device_name.c_str(), filter.c_str(), pcap_path.c_str(),
        packet_printer_callback, &ctx) != 0) {
        std::cerr << "Capturing failed\n";
        return 1;
    }
}
