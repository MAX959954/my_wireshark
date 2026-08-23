#include "ipv6_parser.h"
#include <stddef.h>
#include <stdio.h>

int ipv6_parse(const uint8_t* data, uint32_t length, ipv6_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len) {

    if (data == NULL || out_header == NULL || length < IPV6_HEADER_LEN) {
        return -1;
    }

    uint8_t version = data[0] >> 4;
    if (version != 6) {
        return  -1;
    }

    out_header->version = version;
    out_header->traffic_class = (uint8_t)(((data[0] & 0x0F) << 4) | (data[1] >> 4));
    out_header->flow_label = ((uint32_t)(data[1] & 0x0F) << 16) |
                              ((uint32_t)data[2] << 8) | data[3];

    out_header->payload_length = (uint16_t)((data[4] << 8) | data[5]);
    out_header->next_header = data[6];
    out_header->hop_limit = data[7];

    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        out_header->src_addr[i] = data[8 + i];
        out_header->dst_addr[i] = data[24 + i];
    }

    if (out_payload != NULL){
        *out_payload = data + IPV6_HEADER_LEN;
    }

    if (out_payload_len != NULL) {
        *out_payload_len = length - IPV6_HEADER_LEN;
    }
        
    return 0;
}


void ipv6_addr_to_str(const uint8_t addr[IPV6_ADDR_LEN], char* output) {
    snprintf(output , IPV6_ADDR_STR_LEN , "%x:%x:%x:%x:%x:%x:%x:%x", (addr[0] << 8) | addr[1], (addr[2] << 8) | addr[3],
        (addr[4] << 8) | addr[5], (addr[6] << 8) | addr[7],
        (addr[8] << 8) | addr[9], (addr[10] << 8) | addr[11],
        (addr[12] << 8) | addr[13], (addr[14] << 8) | addr[15]);
}
