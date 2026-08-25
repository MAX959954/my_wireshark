#include "test_util.h"
#include "c/eth_parser.h"
#include <string.h>

static void parses_valid_ipv4_frame(void) {
    uint8_t frame[14] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, /* dst */
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* src */
        0x08, 0x00                          /* ethertype = IPv4 */
    };

    eth_header_t hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;

    int rc = eth_parse(frame, sizeof(frame), &hdr, &payload, &payload_len);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.ether_type == ETH_TYPE_IPV4);
    TEST_ASSERT(hdr.has_vlan == 0);
    TEST_ASSERT(memcmp(hdr.dst_mac, frame, 6) == 0);
    TEST_ASSERT(memcmp(hdr.src_mac, frame + 6, 6) == 0);
    TEST_ASSERT(payload == frame + 14);
    TEST_ASSERT(payload_len == 0);
}

static void rejects_frame_shorter_than_header(void) {
    uint8_t frame[13] = {0};
    eth_header_t hdr;
    TEST_ASSERT(eth_parse(frame, sizeof(frame), &hdr, NULL, NULL) == -1);
}

static void mac_to_str_formats_lowercase_hex(void) {
    uint8_t mac[6] = {0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c};
    char buf[ETH_MAC_STR_LEN];
    eth_mac_to_str(mac, buf);
    TEST_ASSERT(strcmp(buf, "01:02:03:0a:0b:0c") == 0);
}

int main(void) {
    TEST_RUN(parses_valid_ipv4_frame);
    TEST_RUN(rejects_frame_shorter_than_header);
    TEST_RUN(mac_to_str_formats_lowercase_hex);
    TEST_MAIN_END();
}
