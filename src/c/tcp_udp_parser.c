#include "tcp_udp_parser.h"
#include "checksum.h"
#include <stddef.h>

#define IPV4_PROTO_TCP 6
#define IPV4_PROTO_UDP 17

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
    out_header->checksum_valid = 0;

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
    out_header->checksum_present = out_header->checksum != 0;
    out_header->checksum_valid = 0;

    if (out_payload != NULL) {
        *out_payload = data + UDP_HEADER_LEN;
    }

    if (out_payload_len != NULL) {
        *out_payload_len = length - UDP_HEADER_LEN;
    }

    return 0;
}

static int verify_with_ipv4_pseudo_header(const uint8_t* segment, uint32_t segment_len,
    const uint8_t src_ip[4], const uint8_t dst_ip[4], uint8_t protocol) {

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
    pseudo_header[8] = 0;
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

int tcp_verify_checksum(const uint8_t* segment, uint32_t segment_len,
    const uint8_t src_ip[4], const uint8_t dst_ip[4]) {

    if (segment == NULL || src_ip == NULL || dst_ip == NULL || segment_len < TCP_HEADER_MIN_LEN) {
        return 0;
    }

    return verify_with_ipv4_pseudo_header(segment, segment_len, src_ip, dst_ip, IPV4_PROTO_TCP);
}

int udp_verify_checksum(const uint8_t* segment, uint32_t segment_len,
    const uint8_t src_ip[4], const uint8_t dst_ip[4]) {

    uint16_t checksum_field;

    if (segment == NULL || src_ip == NULL || dst_ip == NULL || segment_len < UDP_HEADER_LEN) {
        return 0;
    }

    checksum_field = (uint16_t)((segment[6] << 8) | segment[7]);
    if (checksum_field == 0) {
        return 1;
    }

    return verify_with_ipv4_pseudo_header(segment, segment_len, src_ip, dst_ip, IPV4_PROTO_UDP);
}
