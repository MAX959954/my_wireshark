/* Fuzz target for ipv6_parse() (src/c/ipv6_parser.c). */
#include "c/ipv6_parser.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ipv6_header_t header;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;

    int rc = ipv6_parse(data, (uint32_t)size, &header, &payload, &payload_len);
    if (rc == 0 && payload != NULL) {
        if (payload < data || payload > data + size ||
            payload_len > (uint32_t)(data + size - payload)) {
            __builtin_trap();
        }
    }
    return 0;
}
