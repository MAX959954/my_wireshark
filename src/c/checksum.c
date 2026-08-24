#include "checksum.h"

uint32_t checksum_partial(const uint8_t* data, uint32_t len, uint32_t sum) {
    uint32_t i = 0;

    for (; i + 1 < len; i += 2) {
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += (uint32_t)(data[i] << 8);
    }

    return sum;
}

int checksum_verify(const uint8_t* data, uint32_t len) {
    uint32_t sum = checksum_partial(data, len, 0);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (sum & 0xFFFF) == 0xFFFF;
}
