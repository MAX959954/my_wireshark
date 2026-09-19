/* Fuzz target for icmp_parse() (src/c/icmp_parser.c). */
#include "c/icmp_parser.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    icmp_header_t header;
    icmp_parse(data, (uint32_t)size, ICMP_FAMILY_V4, &header);
    icmp_parse(data, (uint32_t)size, ICMP_FAMILY_V6, &header);
    return 0;
}
