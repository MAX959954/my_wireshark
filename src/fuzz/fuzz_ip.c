/* Fuzz target for ip_parse() (src/c/ip_parser.c), including its
   checksum verification (checksum.c) since ip_parse() always runs it. */
#include "c/ip_parser.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ip_header_t header;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;

    int rc = ip_parse(data, (uint32_t)size, &header, &payload, &payload_len);
    if (rc == 0 && payload != NULL) {
        if (payload < data || payload > data + size || payload_len > (uint32_t)(data + size - payload)) {
            __builtin_trap();
        }
    }
    return 0;
}
