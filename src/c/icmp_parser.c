#include "icmp_parser.h"
#include "checksum.h"
#include <stddef.h>

int icmp_parse(const uint8_t* data, uint32_t length, icmp_family_t family,
               icmp_header_t* out_header) {
    if (data == NULL || out_header == NULL || length < ICMP_HEADER_LEN) {
        return -1;
    }

    out_header->type = data[0];
    out_header->code = data[1];
    out_header->checksum = (uint16_t)((data[2] << 8) | data[3]);
    out_header->checksum_valid = 0;

    uint8_t echo_request_type =
        (family == ICMP_FAMILY_V6) ? ICMPV6_TYPE_ECHO_REQUEST : ICMPV4_TYPE_ECHO_REQUEST;
    uint8_t echo_reply_type =
        (family == ICMP_FAMILY_V6) ? ICMPV6_TYPE_ECHO_REPLY : ICMPV4_TYPE_ECHO_REPLY;

    if (out_header->type == echo_request_type || out_header->type == echo_reply_type) {
        out_header->is_echo = 1;
        out_header->echo_id = (uint16_t)((data[4] << 8) | data[5]);
        out_header->echo_seq = (uint16_t)((data[6] << 8) | data[7]);
    } else {
        out_header->is_echo = 0;
        out_header->echo_id = 0;
        out_header->echo_seq = 0;
    }

    return 0;
}

int icmpv4_verify_checksum(const uint8_t* segment, uint32_t segment_len) {
    if (segment == NULL || segment_len < ICMP_HEADER_LEN) {
        return 0;
    }
    return checksum_verify(segment, segment_len);
}

int icmpv6_verify_checksum(const uint8_t* segment, uint32_t segment_len, const uint8_t src_ip[16],
                           const uint8_t dst_ip[16]) {
    if (segment == NULL || src_ip == NULL || dst_ip == NULL || segment_len < ICMP_HEADER_LEN) {
        return 0;
    }
    return checksum_verify_ipv6_pseudo(segment, segment_len, src_ip, dst_ip, IP_PROTO_ICMPV6);
}
