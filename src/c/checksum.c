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

    /* Fold the carry (one's-complement addition): add the high 16 bits
       back into the low 16 bits. A while loop rather than "if" because the
       fold itself can produce a new carry (0xFFFF + 0x0001 = 0x10000); in
       practice two iterations always suffice, but the loop is correct for
       any input. */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (sum & 0xFFFF) == 0xFFFF;
}

int checksum_verify_ipv4_pseudo(const uint8_t* segment, uint32_t segment_len,
                                const uint8_t src_ip[4], const uint8_t dst_ip[4],
                                uint8_t protocol) {
    uint8_t pseudo_header[12];
    uint32_t sum;

    pseudo_header[0] = src_ip[0];
    pseudo_header[1] = src_ip[1];
    pseudo_header[2] = src_ip[2];
    pseudo_header[3] = src_ip[3];
    pseudo_header[4] = dst_ip[0];
    pseudo_header[5] = dst_ip[1];
    pseudo_header[6] = dst_ip[2];
    pseudo_header[7] = dst_ip[3];
    pseudo_header[8] = 0; /* reserved / zero */
    pseudo_header[9] = protocol;
    pseudo_header[10] = (uint8_t)(segment_len >> 8);
    pseudo_header[11] = (uint8_t)(segment_len & 0xFF);

    sum = checksum_partial(pseudo_header, sizeof(pseudo_header), 0);
    sum = checksum_partial(segment, segment_len, sum);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (sum & 0xFFFF) == 0xFFFF;
}

/*
RFC 2460 section 8.1's IPv6 pseudo-header: 16-byte source, 16-byte
destination, a 32-bit upper-layer packet length, 3 zero bytes, then the
1-byte next-header value:

  +------------------+------------------+
  |  source address (16 bytes)          |
  +------------------+------------------+
  |  destination address (16 bytes)     |
  +------------------+------------------+
  |     upper-layer packet length (4)   |
  +---------+---------+--------+--------+
  |   zero (3 bytes)  | next header (1) |
  +---------+---------+--------+--------+
*/
int checksum_verify_ipv6_pseudo(const uint8_t* segment, uint32_t segment_len,
                                const uint8_t src_ip[16], const uint8_t dst_ip[16],
                                uint8_t next_header) {
    uint8_t pseudo_header[40];
    uint32_t sum;

    for (int i = 0; i < 16; i++) {
        pseudo_header[i] = src_ip[i];
        pseudo_header[16 + i] = dst_ip[i];
    }
    pseudo_header[32] = (uint8_t)(segment_len >> 24);
    pseudo_header[33] = (uint8_t)(segment_len >> 16);
    pseudo_header[34] = (uint8_t)(segment_len >> 8);
    pseudo_header[35] = (uint8_t)(segment_len & 0xFF);
    pseudo_header[36] = 0;
    pseudo_header[37] = 0;
    pseudo_header[38] = 0;
    pseudo_header[39] = next_header;

    sum = checksum_partial(pseudo_header, sizeof(pseudo_header), 0);
    sum = checksum_partial(segment, segment_len, sum);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (sum & 0xFFFF) == 0xFFFF;
}
