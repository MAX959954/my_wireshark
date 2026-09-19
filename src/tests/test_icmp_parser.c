#include "test_util.h"
#include "c/icmp_parser.h"
#include <string.h>

static const uint8_t SRC_IP6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t DST_IP6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

/* ICMPv4 echo request, id=1 seq=1, checksum=0xf7fd (correct: a plain
   Internet checksum over the whole message, no pseudo-header - RFC 792). */
static const uint8_t VALID_ICMPV4_ECHO_REQUEST[ICMP_HEADER_LEN] = {
    0x08, 0x00, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01,
};

/* ICMPv6 echo request, id=1 seq=1, checksum=0x2446 - correct over the
   IPv6 pseudo-header (RFC 4443 SS2.3) for SRC_IP6 -> DST_IP6. */
static const uint8_t VALID_ICMPV6_ECHO_REQUEST[ICMP_HEADER_LEN] = {
    0x80, 0x00, 0x24, 0x46, 0x00, 0x01, 0x00, 0x01,
};

static void parses_icmpv4_echo_request(void) {
    icmp_header_t hdr;
    int rc = icmp_parse(VALID_ICMPV4_ECHO_REQUEST, sizeof(VALID_ICMPV4_ECHO_REQUEST),
                        ICMP_FAMILY_V4, &hdr);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.type == ICMPV4_TYPE_ECHO_REQUEST);
    TEST_ASSERT(hdr.code == 0);
    TEST_ASSERT(hdr.checksum == 0xf7fd);
    TEST_ASSERT(hdr.checksum_valid == 0); /* icmp_parse() never sets this */
    TEST_ASSERT(hdr.is_echo == 1);
    TEST_ASSERT(hdr.echo_id == 1);
    TEST_ASSERT(hdr.echo_seq == 1);
}

static void parses_icmpv4_echo_reply(void) {
    uint8_t data[ICMP_HEADER_LEN];
    memcpy(data, VALID_ICMPV4_ECHO_REQUEST, sizeof(data));
    data[0] = ICMPV4_TYPE_ECHO_REPLY;

    icmp_header_t hdr;
    TEST_ASSERT(icmp_parse(data, sizeof(data), ICMP_FAMILY_V4, &hdr) == 0);
    TEST_ASSERT(hdr.is_echo == 1);
}

static void non_echo_type_leaves_echo_fields_unset(void) {
    uint8_t data[ICMP_HEADER_LEN];
    memcpy(data, VALID_ICMPV4_ECHO_REQUEST, sizeof(data));
    data[0] = ICMPV4_TYPE_DEST_UNREACHABLE;
    data[1] = 3; /* code: port unreachable */

    icmp_header_t hdr;
    TEST_ASSERT(icmp_parse(data, sizeof(data), ICMP_FAMILY_V4, &hdr) == 0);
    TEST_ASSERT(hdr.is_echo == 0);
    TEST_ASSERT(hdr.echo_id == 0);
    TEST_ASSERT(hdr.echo_seq == 0);
    TEST_ASSERT(hdr.code == 3);
}

static void rejects_buffer_shorter_than_header(void) {
    uint8_t data[ICMP_HEADER_LEN - 1];
    memcpy(data, VALID_ICMPV4_ECHO_REQUEST, sizeof(data));
    icmp_header_t hdr;
    TEST_ASSERT(icmp_parse(data, sizeof(data), ICMP_FAMILY_V4, &hdr) == -1);
}

static void v4_type_128_is_not_treated_as_echo(void) {
    /* 128/129 only mean "echo" under ICMPv6 (RFC 4443) - under ICMPv4
       they're unassigned, and definitely not request/reply (0/8). */
    uint8_t data[ICMP_HEADER_LEN];
    memcpy(data, VALID_ICMPV4_ECHO_REQUEST, sizeof(data));
    data[0] = 128;
    icmp_header_t hdr;
    TEST_ASSERT(icmp_parse(data, sizeof(data), ICMP_FAMILY_V4, &hdr) == 0);
    TEST_ASSERT(hdr.is_echo == 0);
}

static void icmpv4_verify_checksum_accepts_a_correct_checksum(void) {
    TEST_ASSERT(
        icmpv4_verify_checksum(VALID_ICMPV4_ECHO_REQUEST, sizeof(VALID_ICMPV4_ECHO_REQUEST)) == 1);
}

static void icmpv4_verify_checksum_rejects_a_corrupted_message(void) {
    uint8_t data[ICMP_HEADER_LEN];
    memcpy(data, VALID_ICMPV4_ECHO_REQUEST, sizeof(data));
    data[4] = 0x99; /* identifier byte changed, checksum field left untouched */
    TEST_ASSERT(icmpv4_verify_checksum(data, sizeof(data)) == 0);
}

static void parses_icmpv6_echo_request(void) {
    icmp_header_t hdr;
    int rc = icmp_parse(VALID_ICMPV6_ECHO_REQUEST, sizeof(VALID_ICMPV6_ECHO_REQUEST),
                        ICMP_FAMILY_V6, &hdr);

    TEST_ASSERT(rc == 0);
    TEST_ASSERT(hdr.type == ICMPV6_TYPE_ECHO_REQUEST);
    TEST_ASSERT(hdr.is_echo == 1);
    TEST_ASSERT(hdr.echo_id == 1);
    TEST_ASSERT(hdr.echo_seq == 1);
}

static void icmpv6_verify_checksum_accepts_a_correct_checksum(void) {
    TEST_ASSERT(icmpv6_verify_checksum(VALID_ICMPV6_ECHO_REQUEST, sizeof(VALID_ICMPV6_ECHO_REQUEST),
                                       SRC_IP6, DST_IP6) == 1);
}

static void icmpv6_verify_checksum_rejects_the_ipv4_checksum_for_the_same_bytes(void) {
    /* Same bytes as VALID_ICMPV4_ECHO_REQUEST would need a different
       checksum once an IPv6 pseudo-header is mixed in - proves the two
       aren't accidentally interchangeable (mirrors the equivalent TCP/UDP
       test in test_tcp_udp_parser.c). */
    TEST_ASSERT(icmpv6_verify_checksum(VALID_ICMPV4_ECHO_REQUEST, sizeof(VALID_ICMPV4_ECHO_REQUEST),
                                       SRC_IP6, DST_IP6) == 0);
}

static void icmpv6_verify_checksum_rejects_a_corrupted_message(void) {
    uint8_t data[ICMP_HEADER_LEN];
    memcpy(data, VALID_ICMPV6_ECHO_REQUEST, sizeof(data));
    data[4] = 0x99;
    TEST_ASSERT(icmpv6_verify_checksum(data, sizeof(data), SRC_IP6, DST_IP6) == 0);
}

int main(void) {
    TEST_RUN(parses_icmpv4_echo_request);
    TEST_RUN(parses_icmpv4_echo_reply);
    TEST_RUN(non_echo_type_leaves_echo_fields_unset);
    TEST_RUN(rejects_buffer_shorter_than_header);
    TEST_RUN(v4_type_128_is_not_treated_as_echo);
    TEST_RUN(icmpv4_verify_checksum_accepts_a_correct_checksum);
    TEST_RUN(icmpv4_verify_checksum_rejects_a_corrupted_message);
    TEST_RUN(parses_icmpv6_echo_request);
    TEST_RUN(icmpv6_verify_checksum_accepts_a_correct_checksum);
    TEST_RUN(icmpv6_verify_checksum_rejects_the_ipv4_checksum_for_the_same_bytes);
    TEST_RUN(icmpv6_verify_checksum_rejects_a_corrupted_message);
    TEST_MAIN_END();
}
