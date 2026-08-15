#include "tcp_udp_parser.h"
#include <stddef.h>

int tcp_parse(const uint8_t* data, uint32_t length, tcp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len) {

    if (data == NULL || out_header == NULL || length < TCP_HEADER_MIN_LEN) {
        return -1;
    }

    uint8_t data_offset = data[12] >> 4;
    uint32_t header_len = (uint32_t)data_offset * 4;

    if (data_offset < 5 || header_len > length) {
        return -1;
    }

    out_header->src_port = (uint16_t)((data[0] << 8) | data[1]);
    out_header->dst_port = (uint16_t)((data[2] << 8) | data[3]);
    out_header->seq_num = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
        ((uint32_t)data[6] << 8) | data[7];
    out_header->ack_num = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
        ((uint32_t)data[10] << 8) | data[11];

    out_header->data_offset = data_offset;
    out_header->flags = data[13] & 0x3F;

    out_header->window_size = (uint16_t)((data[14] << 8) | data[15]);
    out_header->checksum = (uint16_t)((data[16] << 8) | data[17]);
    out_header->urgent_pointer = (uint16_t)((data[18] << 8) | data[19]);

    if (out_payload != NULL) {
        *out_payload = data + header_len;
    }

    if (out_payload_len != NULL) {
        *out_payload_len = length - header_len;
    }

    return 0;
}

int udp_parse(const uint8_t* data, uint32_t length, udp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len) {

    if (data == NULL || out_header == NULL || length < UDP_HEADER_LEN) {
        return -1;
    }

    out_header->src_port = (uint16_t)((data[0] << 8) | data[1]);
    out_header->dst_port = (uint16_t)((data[2] << 8) | data[3]);
    out_header->length = (uint16_t)((data[4] << 8) | data[5]);
    out_header->checksum = (uint16_t)((data[6] << 8) | data[7]);

    if (out_payload != NULL) {
        *out_payload = data + UDP_HEADER_LEN;
    }

    if (out_payload_len != NULL) {
        *out_payload_len = length - UDP_HEADER_LEN;
    }

    return 0;
}
