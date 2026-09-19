#pragma once
#include <cstdint>
#include <ostream>

#include "c/dispfilter.h"

/*
Decodes one captured frame — Ethernet -> ARP/IPv6/IPv4 -> TCP/UDP/ICMP/
other — and writes a one-line summary plus a hex dump to 'os'. This is
the exact decode-and-print pipeline main.cpp runs per packet during live
capture, factored out so it can be driven end-to-end (capture -> parse ->
print) by a fake capture_backend_t in tests, without a real NIC.

'filter' is an optional compiled display filter (see dispfilter.h): when
non-null, a packet whose parsed fields don't match it is parsed (and, in
main.cpp, still written to a .pcap file if -w was given) but not printed
- the userspace counterpart to the kernel-side BPF capture filter (-f).
Pass nullptr (the default) to print every packet, unfiltered.
*/
void print_packet(std::ostream& os, const uint8_t* packet, uint32_t length, uint32_t ts_seconds,
                  uint32_t ts_microseconds, uint64_t packet_number,
                  const dispfilter_t* filter = nullptr);

/*
Adapts print_packet() to the capture_packet_cb ABI capture_backend_run()
expects: numbers packets sequentially starting at 1 and writes each
decoded summary to 'os'. Shared by main.cpp (live capture) and
test_capture_pipeline.cpp (fake capture) so both exercise the identical
callback.
*/
struct PacketPrinterContext {
    explicit PacketPrinterContext(std::ostream& out) : os(out) {}
    std::ostream& os;
    uint64_t count = 0;
    const dispfilter_t* filter = nullptr; /* nullptr = print every packet */
};

void packet_printer_callback(const uint8_t* packet, uint32_t length, uint32_t ts_seconds,
                             uint32_t ts_microseconds, void* user_data);
