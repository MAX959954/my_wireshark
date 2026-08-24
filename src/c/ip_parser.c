#include "ip_parser.h"
#include "checksum.h"
#include <stddef.h>
#include <stdio.h>

int ip_parse(const uint8_t* data, uint32_t length, ip_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len) {

    if (data == NULL || out_header == NULL || length < IP_HEADER_MIN_LEN) {
        return -1;
    }

    uint8_t version = data[0] >> 4;
    uint8_t ihl = data[0] & 0x0F;
    uint32_t header_len = (uint32_t)ihl * 4;

    if (version != 4 || ihl < 5 || header_len > length) {
        return -1;
    }

    out_header->checksum_valid = (uint8_t)checksum_verify(data, header_len);

    out_header->version = version;
    out_header->ihl = ihl;
    out_header->tos = data[1];
    out_header->total_length = (uint16_t)((data[2] << 8) | data[3]);
    out_header->identification = (uint16_t)((data[4] << 8) | data[5]);

    uint16_t flags_frag = (uint16_t)((data[6] << 8) | data[7]);
    out_header->flags = (uint8_t)(flags_frag >> 13);
    out_header->fragment_offset = flags_frag & 0x1FFF;

    out_header->ttl = data[8];
    out_header->protocol = data[9];
    out_header->checksum = (uint16_t)((data[10] << 8) | data[11]);

    out_header->src_addr[0] = data[12];
    out_header->src_addr[1] = data[13];
    out_header->src_addr[2] = data[14];
    out_header->src_addr[3] = data[15];

    out_header->dst_addr[0] = data[16];
    out_header->dst_addr[1] = data[17];
    out_header->dst_addr[2] = data[18];
    out_header->dst_addr[3] = data[19];

    if (out_payload != NULL) {
        *out_payload = data + header_len;
    }

    if (out_payload_len != NULL) {
        uint32_t available_payload_len = length - header_len;

        /* total_length is the authoritative datagram size; anything beyond it
           within the captured frame is L2 padding/trailer (common on short
           packets, e.g. bare TCP ACKs), not part of the IP payload. Only trust
           it when it doesn't exceed what was actually captured — otherwise the
           capture is truncated and available_payload_len is what we've got. */
        if (out_header->total_length >= header_len) {
            uint32_t declared_payload_len = out_header->total_length - header_len;
            if (declared_payload_len < available_payload_len) {
                available_payload_len = declared_payload_len;
            }
        }

        *out_payload_len = available_payload_len;
    }

    return 0;
}

void ip_addr_to_str(const uint8_t addr[IP_ADDR_LEN], char* output) {
    snprintf(output, IP_ADDR_STR_LEN, "%u.%u.%u.%u",
        addr[0], addr[1], addr[2], addr[3]);
}
