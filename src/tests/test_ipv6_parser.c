#include "test_util.h"
#include "c/ipv6_parser.h"
#include <string.h>

/* version=6 traffic_class=0 flow_label=0 payload_length=20 next_header=TCP(6)
   hop_limit=64 src=2001:db8::1 dst=2001:db8::2 */
static const uint8_t VALID_HEADER[IPV6_HEADER_LEN] = {
    0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40,
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};

static void parses_valid_header(void) {
    ipv6_header_t hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0xdeadbeef;

    int rc = ipv6_parse(VALID_HEADER, sizeof(VALID_HEADER), &hdr, &payload, &payload_len);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.version == 6);
    TEST_ASSERT(hdr.traffic_class == 0);
    TEST_ASSERT(hdr.flow_label == 0);
    TEST_ASSERT(hdr.payload_length == 20);
    TEST_ASSERT(hdr.next_header == 6);
    TEST_ASSERT(hdr.hop_limit == 64);
    TEST_ASSERT(memcmp(hdr.src_addr, VALID_HEADER + 8, IPV6_ADDR_LEN) == 0);
    TEST_ASSERT(memcmp(hdr.dst_addr, VALID_HEADER + 24, IPV6_ADDR_LEN) == 0);
    TEST_ASSERT(payload == VALID_HEADER + IPV6_HEADER_LEN);
    TEST_ASSERT(payload_len == 0);
}

static void rejects_buffer_shorter_than_header(void) {
    uint8_t data[IPV6_HEADER_LEN - 1];
    memcpy(data, VALID_HEADER, sizeof(data));
    ipv6_header_t hdr;
    TEST_ASSERT(ipv6_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void rejects_wrong_version(void) {
    uint8_t data[IPV6_HEADER_LEN];
    memcpy(data, VALID_HEADER, sizeof(data));
    data[0] = 0x40; /* version=4, not 6 */
    ipv6_header_t hdr;
    TEST_ASSERT(ipv6_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void addr_to_str_formats_groups_without_leading_zeros(void) {
    /* 2001:0db8:0001:0002:0000:0000:0000:0001 */
    uint8_t addr[IPV6_ADDR_LEN] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    char buf[IPV6_ADDR_STR_LEN];
    ipv6_addr_to_str(addr, buf);
    TEST_ASSERT(strcmp(buf, "2001:db8:1:2:0:0:0:1") == 0);
}

int main(void) {
    TEST_RUN(parses_valid_header);
    TEST_RUN(rejects_buffer_shorter_than_header);
    TEST_RUN(rejects_wrong_version);
    TEST_RUN(addr_to_str_formats_groups_without_leading_zeros);
    TEST_MAIN_END();
}
