#include "eth_parser.h"
#include <stdio.h>
#include <string.h>

int eth_parse(const uint8_t* data, uint32_t length, eth_header_t* out_header,
              const uint8_t** out_payload, uint32_t* out_payload_len) {
    /* length < 14 means the capture was truncated before a full header -
       bail out before any read to avoid running past the buffer. */
    if (data == NULL || out_header == NULL || length < ETH_HEADER_LEN) {
        return -1;
    }

    memcpy(out_header->dst_mac, data, ETH_ADDR_LEN);
    memcpy(out_header->src_mac, data + ETH_ADDR_LEN, ETH_ADDR_LEN);

    /* Not yet known whether this is the real EtherType or a VLAN TPID -
       hence the name. */
    uint16_t type_or_tpid = (uint16_t)((data[12] << 8) | data[13]);
    uint32_t header_len = ETH_HEADER_LEN;

    if (type_or_tpid == ETH_TYPE_VLAN) {
        if (length < ETH_HEADER_LEN + ETH_VLAN_TAG_LEN) {
            return -1;
        }

        out_header->has_vlan = 1;
        out_header->vlan_tci = (uint16_t)((data[14] << 8) | data[15]);
        out_header->ether_type = (uint16_t)((data[16] << 8) | data[17]);
        header_len += ETH_VLAN_TAG_LEN;
    } else {
        out_header->has_vlan = 0;
        out_header->vlan_tci = 0;
        out_header->ether_type = type_or_tpid;
    }

    if (out_payload != NULL) {
        *out_payload = data + header_len;
    }

    if (out_payload_len != NULL) {
        *out_payload_len = length - header_len;
    }

    return 0;
}

void eth_mac_to_str(const uint8_t mac[ETH_ADDR_LEN], char* output) {
    /* ETH_MAC_STR_LEN is sized exactly for this format string, so this can
       never truncate - the return value isn't worth checking (cert-err33-c). */
    (void)snprintf(output, ETH_MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
                   mac[3], mac[4], mac[5]);
}
