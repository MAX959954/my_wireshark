#include "test_util.h"
#include "c/tcp_udp_parser.h"
#include <string.h>

static const uint8_t SRC_IP[4] = {10, 0, 0, 1};
static const uint8_t DST_IP[4] = {10, 0, 0, 2};

/* TCP SYN, src_port=8080 dst_port=80 seq=1 ack=0 data_offset=5 window=0x2000,
   checksum=0x5bff - correct for the IPv4 pseudo-header above. */
static const uint8_t VALID_TCP[TCP_HEADER_MIN_LEN] = {
    0x1f, 0x90, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x5b, 0xff, 0x00, 0x00,
};

/* UDP src_port=12345 dst_port=53 length=12 checksum=0x1dc8 (correct),
   4-byte payload. */
static const uint8_t VALID_UDP[UDP_HEADER_LEN + 4] = {
    0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0x1d, 0xc8, 0xde, 0xad, 0xbe, 0xef,
};

static void tcp_parse_reads_a_valid_header_with_no_options(void) {
    tcp_header_t hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0xdeadbeef;

    int rc = tcp_parse(VALID_TCP, sizeof(VALID_TCP), &hdr, &payload, &payload_len);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.src_port == 8080);
    TEST_ASSERT(hdr.dst_port == 80);
    TEST_ASSERT(hdr.seq_num == 1);
    TEST_ASSERT(hdr.ack_num == 0);
    TEST_ASSERT(hdr.data_offset == 5);
    TEST_ASSERT(hdr.flags == TCP_FLAG_SYN);
    TEST_ASSERT(hdr.window_size == 0x2000);
    TEST_ASSERT(hdr.checksum_valid == 0); /* tcp_parse() never sets this - see tcp_verify_checksum() */
    TEST_ASSERT(payload == VALID_TCP + TCP_HEADER_MIN_LEN);
    TEST_ASSERT(payload_len == 0);
}

static void tcp_parse_rejects_buffer_shorter_than_min_header(void) {
    uint8_t data[TCP_HEADER_MIN_LEN - 1];
    memcpy(data, VALID_TCP, sizeof(data));
    tcp_header_t hdr;
    TEST_ASSERT(tcp_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void tcp_parse_rejects_data_offset_less_than_5(void) {
    uint8_t data[TCP_HEADER_MIN_LEN];
    memcpy(data, VALID_TCP, sizeof(data));
    data[12] = 0x40; /* data_offset=4 */
    tcp_header_t hdr;
    TEST_ASSERT(tcp_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void tcp_parse_rejects_header_len_exceeding_captured_length(void) {
    uint8_t data[TCP_HEADER_MIN_LEN];
    memcpy(data, VALID_TCP, sizeof(data));
    data[12] = 0xf0; /* data_offset=15 -> header_len=60, longer than the 20-byte buffer */
    tcp_header_t hdr;
    TEST_ASSERT(tcp_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void tcp_verify_checksum_accepts_a_correct_checksum(void) {
    TEST_ASSERT(tcp_verify_checksum(VALID_TCP, sizeof(VALID_TCP), SRC_IP, DST_IP) == 1);
}

static void tcp_verify_checksum_rejects_a_corrupted_segment(void) {
    uint8_t data[TCP_HEADER_MIN_LEN];
    memcpy(data, VALID_TCP, sizeof(data));
    data[14] = 0x30; /* window byte changed, checksum field left untouched */
    TEST_ASSERT(tcp_verify_checksum(data, sizeof(data), SRC_IP, DST_IP) == 0);
}

static void udp_parse_reads_a_valid_header_with_payload(void) {
    udp_header_t hdr;
    const uint8_t* payload = NULL;
    uint32_t payload_len = 0;

    int rc = udp_parse(VALID_UDP, sizeof(VALID_UDP), &hdr, &payload, &payload_len);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.src_port == 12345);
    TEST_ASSERT(hdr.dst_port == 53);
    TEST_ASSERT(hdr.length == 12);
    TEST_ASSERT(hdr.checksum == 0x1dc8);
    TEST_ASSERT(hdr.checksum_present == 1);
    TEST_ASSERT(payload == VALID_UDP + UDP_HEADER_LEN);
    TEST_ASSERT(payload_len == 4);
}

static void udp_parse_checksum_present_is_false_when_checksum_field_is_zero(void) {
    uint8_t data[sizeof(VALID_UDP)];
    memcpy(data, VALID_UDP, sizeof(data));
    data[6] = 0x00;
    data[7] = 0x00;

    udp_header_t hdr;
    TEST_ASSERT(udp_parse(data, sizeof(data), &hdr, NULL, NULL) == 0);
    TEST_ASSERT(hdr.checksum_present == 0);
}

static void udp_parse_rejects_buffer_shorter_than_header(void) {
    uint8_t data[UDP_HEADER_LEN - 1];
    memcpy(data, VALID_UDP, sizeof(data));
    udp_header_t hdr;
    TEST_ASSERT(udp_parse(data, sizeof(data), &hdr, NULL, NULL) == -1);
}

static void udp_verify_checksum_accepts_a_correct_checksum(void) {
    TEST_ASSERT(udp_verify_checksum(VALID_UDP, sizeof(VALID_UDP), SRC_IP, DST_IP) == 1);
}

static void udp_verify_checksum_treats_a_zero_checksum_field_as_valid(void) {
    /* RFC 768: checksum == 0 means the sender chose not to compute one. */
    uint8_t data[sizeof(VALID_UDP)];
    memcpy(data, VALID_UDP, sizeof(data));
    data[6] = 0x00;
    data[7] = 0x00;
    TEST_ASSERT(udp_verify_checksum(data, sizeof(data), SRC_IP, DST_IP) == 1);
}

int main(void) {
    TEST_RUN(tcp_parse_reads_a_valid_header_with_no_options);
    TEST_RUN(tcp_parse_rejects_buffer_shorter_than_min_header);
    TEST_RUN(tcp_parse_rejects_data_offset_less_than_5);
    TEST_RUN(tcp_parse_rejects_header_len_exceeding_captured_length);
    TEST_RUN(tcp_verify_checksum_accepts_a_correct_checksum);
    TEST_RUN(tcp_verify_checksum_rejects_a_corrupted_segment);
    TEST_RUN(udp_parse_reads_a_valid_header_with_payload);
    TEST_RUN(udp_parse_checksum_present_is_false_when_checksum_field_is_zero);
    TEST_RUN(udp_parse_rejects_buffer_shorter_than_header);
    TEST_RUN(udp_verify_checksum_accepts_a_correct_checksum);
    TEST_RUN(udp_verify_checksum_treats_a_zero_checksum_field_as_valid);
    TEST_MAIN_END();
}
