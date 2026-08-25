#include "test_util.h"
#include "c/arp_parser.h"
#include <string.h>

static void parses_valid_arp_request(void) {
    uint8_t data[ARP_HEADER_LEN] = {
        0x00, 0x01,                         /* hardware_type = Ethernet */
        0x08, 0x00,                         /* protocol_type = IPv4 */
        0x06, 0x04,                         /* hardware_addr_len, protocol_addr_len */
        0x00, 0x01,                         /* opcode = request */
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* sender_mac */
        192, 168, 1, 1,                     /* sender_ip */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* target_mac (unknown in a request) */
        192, 168, 1, 2,                     /* target_ip */
    };

    arp_header_t hdr;
    int rc = arp_parse(data, sizeof(data), &hdr);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.hardware_type == ARP_HTYPE_ETHERNET);
    TEST_ASSERT(hdr.protocol_type == ARP_PTYPE_IPV4);
    TEST_ASSERT(hdr.hardware_addr_len == 6);
    TEST_ASSERT(hdr.protocol_addr_len == 4);
    TEST_ASSERT(hdr.opcode == ARP_OP_REQUEST);
    TEST_ASSERT(memcmp(hdr.sender_mac, data + 8, 6) == 0);
    TEST_ASSERT(memcmp(hdr.sender_ip, data + 14, 4) == 0);
    TEST_ASSERT(memcmp(hdr.target_mac, data + 18, 6) == 0);
    TEST_ASSERT(memcmp(hdr.target_ip, data + 24, 4) == 0);
}

static void rejects_buffer_shorter_than_header(void) {
    uint8_t data[ARP_HEADER_LEN - 1] = {0};
    arp_header_t hdr;
    TEST_ASSERT(arp_parse(data, sizeof(data), &hdr) == -1);
}

static void rejects_non_ethernet_hardware_type(void) {
    uint8_t data[ARP_HEADER_LEN] = {
        0x00, 0x06, /* hardware_type = 6 (IEEE 802 Networks), not Ethernet */
        0x08, 0x00,
        0x06, 0x04,
        0x00, 0x01,
    };
    arp_header_t hdr;
    TEST_ASSERT(arp_parse(data, sizeof(data), &hdr) == -1);
}

static void rejects_non_ipv4_protocol_type(void) {
    uint8_t data[ARP_HEADER_LEN] = {
        0x00, 0x01,
        0x86, 0xdd, /* protocol_type = IPv6, not IPv4 */
        0x06, 0x04,
        0x00, 0x01,
    };
    arp_header_t hdr;
    TEST_ASSERT(arp_parse(data, sizeof(data), &hdr) == -1);
}

int main(void) {
    TEST_RUN(parses_valid_arp_request);
    TEST_RUN(rejects_buffer_shorter_than_header);
    TEST_RUN(rejects_non_ethernet_hardware_type);
    TEST_RUN(rejects_non_ipv4_protocol_type);
    TEST_MAIN_END();
}
