#include "ip_parser.h"
#include "checksum.h"
#include <stddef.h>
#include <stdio.h>

int ip_parse(const uint8_t* data, uint32_t length, ip_header_t* out_header,
             const uint8_t** out_payload, uint32_t* out_payload_len) {
    if (data == NULL || out_header == NULL || length < IP_HEADER_MIN_LEN) {
        return -1;
    }

    /* version and IHL share one byte, 4 bits each - same trick as the
       VLAN TCI field. */
    uint8_t version = data[0] >> 4;
    uint8_t ihl = data[0] & 0x0F;
    uint32_t header_len = (uint32_t)ihl * 4; /* IHL is in 32-bit words */

    if (version != 4 || ihl < 5 || header_len > length) {
        return -1;
    }

    out_header->checksum_valid = (uint8_t)checksum_verify(data, header_len);

    out_header->version = version;
    out_header->ihl = ihl;
    out_header->tos = data[1];

    /* Fields are assembled byte-by-byte rather than read through a
       uint16_t* because the wire is big-endian and the host may not be. */
    out_header->total_length = (uint16_t)((data[2] << 8) | data[3]);
    out_header->identification = (uint16_t)((data[4] << 8) | data[5]);

    uint16_t flags_frag = (uint16_t)((data[6] << 8) | data[7]);
    out_header->flags = (uint8_t)(flags_frag >> 13);   /* top 3 bits: R, DF, MF */
    out_header->fragment_offset = flags_frag & 0x1FFF; /* low 13 bits */

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

    /*
    'total_length' and the captured buffer can disagree for two reasons:
    Ethernet pads short frames (e.g. a bare TCP ACK) up to a 60-byte
    minimum, so the buffer can hold trailing padding that isn't part of
    the IP datagram; or the capture was truncated (snaplen) and holds less
    than 'total_length' claims. Take the smaller of the two - trusting
    'total_length' over an actually-short buffer would let tcp_parse read
    past the end, and trusting the buffer over a shorter 'total_length'
    would hand the L4 checksum trailing padding it was never computed
    over.
    */
    if (out_payload_len != NULL) {
        uint32_t available_payload_len = length - header_len;

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
    snprintf(output, IP_ADDR_STR_LEN, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}
