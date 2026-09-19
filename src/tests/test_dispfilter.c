#include "test_util.h"
#include "c/dispfilter.h"
#include <string.h>

static dispfilter_fields_t make_fields_tcp(void) {
    dispfilter_fields_t f;
    memset(&f, 0, sizeof(f));
    memcpy(f.eth_src, "\xaa\xbb\xcc\xdd\xee\xff", 6);
    memcpy(f.eth_dst, "\x11\x22\x33\x44\x55\x66", 6);
    f.has_ip = 1;
    memcpy(f.ip_src, (uint8_t[4]){10, 0, 0, 1}, 4);
    memcpy(f.ip_dst, (uint8_t[4]){93, 184, 216, 34}, 4);
    f.has_tcp = 1;
    f.tcp_src_port = 51234;
    f.tcp_dst_port = 443;
    return f;
}

static dispfilter_fields_t make_fields_ipv6_udp(void) {
    dispfilter_fields_t f;
    memset(&f, 0, sizeof(f));
    f.has_ipv6 = 1;
    /* 2001:db8::1 -> 2001:db8::2 */
    uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    memcpy(f.ipv6_src, src, 16);
    memcpy(f.ipv6_dst, dst, 16);
    f.has_udp = 1;
    f.udp_src_port = 12345;
    f.udp_dst_port = 53;
    return f;
}

static void null_expression_matches_everything(void) {
    dispfilter_t* filter = dispfilter_compile(NULL, NULL, 0);
    TEST_ASSERT(filter != NULL);
    dispfilter_fields_t f;
    memset(&f, 0, sizeof(f));
    TEST_ASSERT(dispfilter_matches(filter, &f) == 1);
    dispfilter_free(filter);
}

static void empty_expression_matches_everything(void) {
    dispfilter_t* filter = dispfilter_compile("", NULL, 0);
    TEST_ASSERT(filter != NULL);
    dispfilter_fields_t f = make_fields_tcp();
    TEST_ASSERT(dispfilter_matches(filter, &f) == 1);
    dispfilter_free(filter);
}

static void matches_tcp_port_on_either_side(void) {
    dispfilter_fields_t f = make_fields_tcp();

    dispfilter_t* dst_filter = dispfilter_compile("tcp.port == 443", NULL, 0);
    TEST_ASSERT(dst_filter != NULL);
    TEST_ASSERT(dispfilter_matches(dst_filter, &f) == 1);
    dispfilter_free(dst_filter);

    dispfilter_t* src_filter = dispfilter_compile("tcp.port == 51234", NULL, 0);
    TEST_ASSERT(dispfilter_matches(src_filter, &f) == 1);
    dispfilter_free(src_filter);

    dispfilter_t* no_match = dispfilter_compile("tcp.port == 8080", NULL, 0);
    TEST_ASSERT(dispfilter_matches(no_match, &f) == 0);
    dispfilter_free(no_match);
}

static void srcport_dstport_are_directional(void) {
    dispfilter_fields_t f = make_fields_tcp();

    dispfilter_t* wrong_dir = dispfilter_compile("tcp.srcport == 443", NULL, 0);
    TEST_ASSERT(dispfilter_matches(wrong_dir, &f) == 0);
    dispfilter_free(wrong_dir);

    dispfilter_t* right_dir = dispfilter_compile("tcp.dstport == 443", NULL, 0);
    TEST_ASSERT(dispfilter_matches(right_dir, &f) == 1);
    dispfilter_free(right_dir);
}

static void tcp_port_filter_does_not_match_a_udp_only_packet(void) {
    dispfilter_fields_t f = make_fields_ipv6_udp();
    dispfilter_t* filter = dispfilter_compile("tcp.port == 53", NULL, 0);
    TEST_ASSERT(dispfilter_matches(filter, &f) == 0);
    dispfilter_free(filter);
}

static void matches_ip_src_and_ip_addr(void) {
    dispfilter_fields_t f = make_fields_tcp();

    dispfilter_t* src = dispfilter_compile("ip.src == 10.0.0.1", NULL, 0);
    TEST_ASSERT(dispfilter_matches(src, &f) == 1);
    dispfilter_free(src);

    dispfilter_t* not_src = dispfilter_compile("ip.src == 93.184.216.34", NULL, 0);
    TEST_ASSERT(dispfilter_matches(not_src, &f) == 0);
    dispfilter_free(not_src);

    dispfilter_t* addr = dispfilter_compile("ip.addr == 93.184.216.34", NULL, 0);
    TEST_ASSERT(dispfilter_matches(addr, &f) == 1);
    dispfilter_free(addr);
}

static void ip_filter_does_not_match_an_ipv6_only_packet(void) {
    dispfilter_fields_t f = make_fields_ipv6_udp();
    dispfilter_t* filter = dispfilter_compile("ip.src == 10.0.0.1", NULL, 0);
    TEST_ASSERT(dispfilter_matches(filter, &f) == 0);
    dispfilter_free(filter);
}

static void matches_ipv6_with_double_colon_compression(void) {
    dispfilter_fields_t f = make_fields_ipv6_udp();

    dispfilter_t* src = dispfilter_compile("ipv6.src == 2001:db8::1", NULL, 0);
    TEST_ASSERT(src != NULL);
    TEST_ASSERT(dispfilter_matches(src, &f) == 1);
    dispfilter_free(src);

    dispfilter_t* dst = dispfilter_compile("ipv6.dst == 2001:db8::2", NULL, 0);
    TEST_ASSERT(dispfilter_matches(dst, &f) == 1);
    dispfilter_free(dst);

    dispfilter_t* addr_no_match = dispfilter_compile("ipv6.addr == ::1", NULL, 0);
    TEST_ASSERT(dispfilter_matches(addr_no_match, &f) == 0);
    dispfilter_free(addr_no_match);
}

static void matches_eth_src_mac_literal(void) {
    dispfilter_fields_t f = make_fields_tcp();
    dispfilter_t* filter = dispfilter_compile("eth.src == aa:bb:cc:dd:ee:ff", NULL, 0);
    TEST_ASSERT(filter != NULL);
    TEST_ASSERT(dispfilter_matches(filter, &f) == 1);
    dispfilter_free(filter);
}

static void not_negates_a_primitive(void) {
    dispfilter_fields_t f = make_fields_tcp();
    dispfilter_t* filter = dispfilter_compile("not tcp.port == 443", NULL, 0);
    TEST_ASSERT(dispfilter_matches(filter, &f) == 0);
    dispfilter_free(filter);

    dispfilter_t* not_eq = dispfilter_compile("tcp.port != 443", NULL, 0);
    TEST_ASSERT(dispfilter_matches(not_eq, &f) == 0);
    dispfilter_free(not_eq);
}

static void and_or_combine_with_correct_precedence(void) {
    dispfilter_fields_t f = make_fields_tcp();

    /* 'and' binds tighter than 'or': "ip.src==X or ip.src==Y and tcp.port==443"
       parses as "ip.src==X or (ip.src==Y and tcp.port==443)". */
    dispfilter_t* filter =
        dispfilter_compile("ip.src == 1.2.3.4 or ip.src == 10.0.0.1 and tcp.port == 443", NULL, 0);
    TEST_ASSERT(filter != NULL);
    TEST_ASSERT(dispfilter_matches(filter, &f) == 1);
    dispfilter_free(filter);

    dispfilter_t* parens = dispfilter_compile(
        "(ip.src == 1.2.3.4 or ip.src == 10.0.0.1) and tcp.port == 8080", NULL, 0);
    TEST_ASSERT(dispfilter_matches(parens, &f) == 0);
    dispfilter_free(parens);
}

static void rejects_unknown_field(void) {
    char err[128];
    dispfilter_t* filter = dispfilter_compile("bogus.field == 1", err, sizeof(err));
    TEST_ASSERT(filter == NULL);
    TEST_ASSERT(strlen(err) > 0);
}

static void rejects_missing_operator(void) {
    dispfilter_t* filter = dispfilter_compile("tcp.port 443", NULL, 0);
    TEST_ASSERT(filter == NULL);
}

static void rejects_port_out_of_range(void) {
    dispfilter_t* filter = dispfilter_compile("tcp.port == 70000", NULL, 0);
    TEST_ASSERT(filter == NULL);
}

static void rejects_wrong_value_type_for_field(void) {
    dispfilter_t* filter = dispfilter_compile("tcp.port == 10.0.0.1", NULL, 0);
    TEST_ASSERT(filter == NULL);
}

static void rejects_trailing_garbage(void) {
    dispfilter_t* filter = dispfilter_compile("tcp.port == 443 tcp.port == 80", NULL, 0);
    TEST_ASSERT(filter == NULL);
}

int main(void) {
    TEST_RUN(null_expression_matches_everything);
    TEST_RUN(empty_expression_matches_everything);
    TEST_RUN(matches_tcp_port_on_either_side);
    TEST_RUN(srcport_dstport_are_directional);
    TEST_RUN(tcp_port_filter_does_not_match_a_udp_only_packet);
    TEST_RUN(matches_ip_src_and_ip_addr);
    TEST_RUN(ip_filter_does_not_match_an_ipv6_only_packet);
    TEST_RUN(matches_ipv6_with_double_colon_compression);
    TEST_RUN(matches_eth_src_mac_literal);
    TEST_RUN(not_negates_a_primitive);
    TEST_RUN(and_or_combine_with_correct_precedence);
    TEST_RUN(rejects_unknown_field);
    TEST_RUN(rejects_missing_operator);
    TEST_RUN(rejects_port_out_of_range);
    TEST_RUN(rejects_wrong_value_type_for_field);
    TEST_RUN(rejects_trailing_garbage);
    TEST_MAIN_END();
}
