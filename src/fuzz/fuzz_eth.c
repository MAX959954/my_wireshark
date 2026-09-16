/* Fuzz target for eth_parse() (src/c/eth_parser.c). See README's Fuzzing
   section for how to build and run this either as a real libFuzzer
   binary (clang) or replayed against the seed corpus (any compiler). */
#include "c/eth_parser.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    eth_header_t header;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;

    eth_parse(data, (uint32_t)size, &header, &payload, &payload_len);

    /* eth_parse's whole contract is "never read past data[0..size)" - the
       one thing worth asserting here (beyond what ASan already catches on
       any out-of-bounds read) is that the payload pointer it hands back,
       if any, actually lands inside that same buffer. */
    if (payload != NULL) {
        if (payload < data || payload > data + size || payload_len > (uint32_t)(data + size - payload)) {
            __builtin_trap();
        }
    }
    return 0;
}
