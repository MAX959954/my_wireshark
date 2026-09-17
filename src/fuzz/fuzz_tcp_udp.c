/* Fuzz target for tcp_parse()/udp_parse() and their checksum verification
   (src/c/tcp_udp_parser.c). Both parsers are exercised against the same
   input - they're independent, dependency-free functions, so there's no
   need for two separate harnesses/corpora. */
#include "c/tcp_udp_parser.h"

#include <stddef.h>
#include <stdint.h>

static const uint8_t DUMMY_SRC_IP[4] = {192, 168, 1, 10};
static const uint8_t DUMMY_DST_IP[4] = {93, 184, 216, 34};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    tcp_header_t tcp_header;
    const uint8_t* tcp_payload = NULL;
    uint32_t tcp_payload_len = 0;
    if (tcp_parse(data, (uint32_t)size, &tcp_header, &tcp_payload, &tcp_payload_len) == 0) {
        if (tcp_payload < data || tcp_payload > data + size ||
            tcp_payload_len > (uint32_t)(data + size - tcp_payload)) {
            __builtin_trap();
        }
    }
    tcp_verify_checksum(data, (uint32_t)size, DUMMY_SRC_IP, DUMMY_DST_IP);

    udp_header_t udp_header;
    const uint8_t* udp_payload = NULL;
    uint32_t udp_payload_len = 0;
    if (udp_parse(data, (uint32_t)size, &udp_header, &udp_payload, &udp_payload_len) == 0) {
        if (udp_payload < data || udp_payload > data + size ||
            udp_payload_len > (uint32_t)(data + size - udp_payload)) {
            __builtin_trap();
        }
    }
    udp_verify_checksum(data, (uint32_t)size, DUMMY_SRC_IP, DUMMY_DST_IP);

    return 0;
}
