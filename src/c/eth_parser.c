#include "eth_parser.h"
#include <stdio.h>
#include <string.h>

int eth_parse(const uint8_t* data, uint32_t length, eth_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len) {

    if (data == NULL || out_header == NULL || length < ETH_HEADER_LEN) {
        return -1;
    }

    memcpy(out_header->dst_mac, data, ETH_ADDR_LEN);
    memcpy(out_header->src_mac, data + ETH_ADDR_LEN, ETH_ADDR_LEN);
    out_header->ether_type = (uint16_t)((data[12] << 8) | data[13]);

    if (out_payload != NULL) {
        *out_payload = data + ETH_HEADER_LEN;
    }

    if (out_payload_len != NULL) {
        *out_payload_len = length - ETH_HEADER_LEN;
    }

    return 0;
}

void eth_mac_to_str(const uint8_t mac[ETH_ADDR_LEN], char* output) {
    snprintf(output, ETH_MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
