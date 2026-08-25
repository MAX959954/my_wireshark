#include "test_util.h"
#include "c/ip_parser.h"
#include <string.h>

/* version=4 ihl=5 tos=0 total_length=40 id=0xab12 flags/frag=0 ttl=64
   protocol=TCP(6) checksum=0xd830 (correct) src=192.168.1.10 dst=93.184.216.34 */
static const uint8_t VALID_HEADER[IP_HEADER_MIN_LEN] = {
    0x45, 0x00, 0x00, 0x28, 0xab, 0x12, 0x00, 0x00, 0x40, 0x06,
    0xd8, 0x30, 192, 168, 1, 10, 93, 184, 216, 34,
};

static void parses_valid_header_with_correct_checksum(void) {
    ip_header_t hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0xdeadbeef;

    int rc = ip_parse(VALID_HEADER, sizeof(VALID_HEADER), &hdr, &payload, &payload_len);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.version == 4);
    TEST_ASSERT(hdr.ihl == 5);
    TEST_ASSERT(hdr.tos == 0);
    TEST_ASSERT(hdr.total_length == 40);
    TEST_ASSERT(hdr.identification == 0xab12);
    TEST_ASSERT(hdr.flags == 0);
    TEST_ASSERT(hdr.fragment_offset == 0);
    TEST_ASSERT(hdr.ttl == 64);
    TEST_ASSERT(hdr.protocol == IP_PROTO_TCP);
    TEST_ASSERT(hdr.checksum_valid == 1);

    char src_str[IP_ADDR_STR_LEN];
    char dst_str[IP_ADDR_STR_LEN];
    ip_addr_to_str(hdr.src_addr, src_str);
    ip_addr_to_str(hdr.dst_addr, dst_str);
    TEST_ASSERT(strcmp(src_str, "192.168.1.10") == 0);
    TEST_ASSERT(strcmp(dst_str, "93.184.216.34") == 0);

    TEST_ASSERT(payload == VALID_HEADER + IP_HEADER_MIN_LEN);
    TEST_ASSERT(payload_len == 0); /* no bytes captured past the 20-byte header */
}

static void checksum_valid_is_false_when_header_is_corrupted(void) {
    uint8_t data[IP_HEADER_MIN_LEN];
    memcpy(data, VALID_HEADER, sizeof(data));
    data[8] = 0x41; /* flip the TTL byte without touching the checksum field */

    ip_header_t hdr;
    int rc = ip_parse(data, sizeof(data), &hdr, NULL, NULL);

    TEST_ASSERT(rc == 0); /* a bad checksum doesn't make ip_parse() fail */
    TEST_ASSERT(hdr.checksum_valid == 0);
}

static void rejects_buffer_shorter_than_min_header(void) {
    uint8_t data[IP_HEADER_MIN_LEN - 1];
    memcpy(data, VALID_HEADER, sizeof(data));
    ip_header_t hdr;
    TEST_ASSERT(ip_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void rejects_wrong_version(void) {
    uint8_t data[IP_HEADER_MIN_LEN];
    memcpy(data, VALID_HEADER, sizeof(data));
    data[0] = 0x65; /* version=6, ihl=5 */
    ip_header_t hdr;
    TEST_ASSERT(ip_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void rejects_ihl_less_than_5(void) {
    uint8_t data[IP_HEADER_MIN_LEN];
    memcpy(data, VALID_HEADER, sizeof(data));
    data[0] = 0x44; /* version=4, ihl=4 (below the 20-byte minimum) */
    ip_header_t hdr;
    TEST_ASSERT(ip_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void rejects_header_len_exceeding_captured_length(void) {
    uint8_t data[IP_HEADER_MIN_LEN];
    memcpy(data, VALID_HEADER, sizeof(data));
    data[0] = 0x4f; /* version=4, ihl=15 -> header_len=60, longer than the 20-byte buffer */
    ip_header_t hdr;
    TEST_ASSERT(ip_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void clips_payload_len_to_declared_total_length(void) {
    /* 20-byte header (total_length=25, i.e. 5 bytes of real payload) followed
       by 10 captured bytes - the extra 5 are L2 trailer/padding, not payload. */
    uint8_t data[30] = {
        0x45, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
        0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    };

    ip_header_t hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;
    int rc = ip_parse(data, sizeof(data), &hdr, &payload, &payload_len);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(payload == data + 20);
    TEST_ASSERT(payload_len == 5);
}

int main(void) {
    TEST_RUN(parses_valid_header_with_correct_checksum);
    TEST_RUN(checksum_valid_is_false_when_header_is_corrupted);
    TEST_RUN(rejects_buffer_shorter_than_min_header);
    TEST_RUN(rejects_wrong_version);
    TEST_RUN(rejects_ihl_less_than_5);
    TEST_RUN(rejects_header_len_exceeding_captured_length);
    TEST_RUN(clips_payload_len_to_declared_total_length);
    TEST_MAIN_END();
}
