/* Fuzz target for arp_parse() (src/c/arp_parser.c). */
#include "c/arp_parser.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    arp_header_t header;
    arp_parse(data, (uint32_t)size, &header);
    return 0;
}
