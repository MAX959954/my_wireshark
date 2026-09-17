#include "test_util.h"
#include "bpf_interp.h"
#include "c/capfilter.h"

#include <string.h>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806

static void put16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Builds a 14-byte Ethernet + 20-byte IPv4 (no options) + optional 4-byte
   TCP/UDP port pair (src/dst, that's all this filter's codegen ever looks
   at) frame into 'buf' (must be >= 38 bytes). Returns the frame length. */
static uint32_t build_frame(uint8_t* buf, uint8_t ip_proto, const uint8_t src_ip[4],
                            const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port) {
    memset(buf, 0, 38);
    put16(buf + 12, ETHERTYPE_IPV4);
    buf[14] = 0x45; /* version=4, ihl=5 (20-byte header, no options) */
    buf[23] = ip_proto;
    memcpy(buf + 26, src_ip, 4);
    memcpy(buf + 30, dst_ip, 4);
    put16(buf + 34, src_port);
    put16(buf + 36, dst_port);
    return 38;
}

static uint32_t build_arp_frame(uint8_t* buf) {
    memset(buf, 0, 14);
    put16(buf + 12, ETHERTYPE_ARP);
    return 14;
}

static const uint8_t IP_A[4] = {10, 0, 0, 5};
static const uint8_t IP_B[4] = {10, 0, 1, 7};
static const uint8_t IP_C[4] = {192, 168, 1, 1};

static int accepts(const char* expr, const uint8_t* pkt, uint32_t len) {
    struct sock_fprog prog;
    char err[128] = {0};
    int rc = capfilter_compile(expr, &prog, err, sizeof(err));
    TEST_ASSERT(rc == 0);
    if (rc != 0) {
        fprintf(stderr, "  compile error for '%s': %s\n", expr, err);
        return 0;
    }
    uint32_t verdict = bpf_interp_run(&prog, pkt, len);
    capfilter_free(&prog);
    return verdict != 0;
}

static void empty_expression_accepts_everything(void) {
    struct sock_fprog prog;
    int rc = capfilter_compile(NULL, &prog, NULL, 0);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(prog.filter == NULL);
    TEST_ASSERT(prog.len == 0);
    capfilter_free(&prog); /* must be a safe no-op on an already-empty program */

    rc = capfilter_compile("", &prog, NULL, 0);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(prog.filter == NULL);
}

static void tcp_matches_only_tcp_over_ipv4(void) {
    uint8_t tcp_pkt[38], udp_pkt[38], arp_pkt[14];
    build_frame(tcp_pkt, 6 /* TCP */, IP_A, IP_B, 1234, 80);
    build_frame(udp_pkt, 17 /* UDP */, IP_A, IP_B, 1234, 80);
    build_arp_frame(arp_pkt);

    TEST_ASSERT(accepts("tcp", tcp_pkt, sizeof(tcp_pkt)));
    TEST_ASSERT(!accepts("tcp", udp_pkt, sizeof(udp_pkt)));
    TEST_ASSERT(!accepts("tcp", arp_pkt, sizeof(arp_pkt)));
    TEST_ASSERT(accepts("udp", udp_pkt, sizeof(udp_pkt)));
    TEST_ASSERT(accepts("arp", arp_pkt, sizeof(arp_pkt)));
    TEST_ASSERT(!accepts("arp", tcp_pkt, sizeof(tcp_pkt)));
}

static void port_matches_either_direction_on_tcp_or_udp(void) {
    uint8_t pkt[38];
    build_frame(pkt, 6, IP_A, IP_B, 12345, 443);

    TEST_ASSERT(accepts("port 443", pkt, sizeof(pkt)));
    TEST_ASSERT(accepts("dst port 443", pkt, sizeof(pkt)));
    TEST_ASSERT(!accepts("src port 443", pkt, sizeof(pkt)));
    TEST_ASSERT(accepts("src port 12345", pkt, sizeof(pkt)));
    TEST_ASSERT(!accepts("port 22", pkt, sizeof(pkt)));

    uint8_t icmp_pkt[38];
    build_frame(icmp_pkt, 1 /* ICMP */, IP_A, IP_B, 443, 443);
    TEST_ASSERT(!accepts("port 443", icmp_pkt, sizeof(icmp_pkt))); /* port only means TCP/UDP */
}

static void host_and_net_match_ip_addresses(void) {
    uint8_t pkt[38];
    build_frame(pkt, 6, IP_A, IP_C, 1, 1);

    TEST_ASSERT(accepts("host 10.0.0.5", pkt, sizeof(pkt)));    /* matches src */
    TEST_ASSERT(accepts("host 192.168.1.1", pkt, sizeof(pkt))); /* matches dst */
    TEST_ASSERT(!accepts("host 10.0.1.7", pkt, sizeof(pkt)));
    TEST_ASSERT(accepts("src host 10.0.0.5", pkt, sizeof(pkt)));
    TEST_ASSERT(!accepts("dst host 10.0.0.5", pkt, sizeof(pkt)));

    TEST_ASSERT(accepts("net 10.0.0.0/24", pkt, sizeof(pkt))); /* src is in 10.0.0.0/24 */
    TEST_ASSERT(!accepts("net 10.0.1.0/24", pkt, sizeof(pkt)));
    TEST_ASSERT(accepts("dst net 192.168.1.0/24", pkt, sizeof(pkt)));
}

static void boolean_combinators_compose(void) {
    uint8_t tcp_443[38], tcp_22[38], udp_443[38];
    build_frame(tcp_443, 6, IP_A, IP_B, 5000, 443);
    build_frame(tcp_22, 6, IP_A, IP_B, 5000, 22);
    build_frame(udp_443, 17, IP_A, IP_B, 5000, 443);

    TEST_ASSERT(accepts("tcp and (port 80 or port 443)", tcp_443, sizeof(tcp_443)));
    TEST_ASSERT(!accepts("tcp and (port 80 or port 443)", tcp_22, sizeof(tcp_22)));
    TEST_ASSERT(!accepts("tcp and (port 80 or port 443)", udp_443, sizeof(udp_443)));

    TEST_ASSERT(accepts("not tcp", udp_443, sizeof(udp_443)));
    TEST_ASSERT(!accepts("not tcp", tcp_443, sizeof(tcp_443)));

    uint8_t arp_pkt[14];
    build_arp_frame(arp_pkt);
    TEST_ASSERT(accepts("ip or arp", tcp_443, sizeof(tcp_443)));
    TEST_ASSERT(accepts("ip or arp", arp_pkt, sizeof(arp_pkt)));
    TEST_ASSERT(
        !accepts("ip and arp", arp_pkt, sizeof(arp_pkt))); /* mutually exclusive by ethertype */
}

static void compile_error_cases_report_failure(void) {
    struct sock_fprog prog;
    char err[128];

    TEST_ASSERT(capfilter_compile("tcp and", &prog, err, sizeof(err)) == -1);
    TEST_ASSERT(err[0] != '\0');

    TEST_ASSERT(capfilter_compile("bogus_keyword", &prog, err, sizeof(err)) == -1);
    TEST_ASSERT(capfilter_compile("port 70000", &prog, err, sizeof(err)) == -1);
    TEST_ASSERT(capfilter_compile("net 10.0.0.0/33", &prog, err, sizeof(err)) == -1);
    TEST_ASSERT(capfilter_compile("host 999.1.1.1", &prog, err, sizeof(err)) == -1);
    TEST_ASSERT(capfilter_compile("(tcp", &prog, err, sizeof(err)) == -1);
    TEST_ASSERT(capfilter_compile("src tcp", &prog, err, sizeof(err)) == -1);
}

int main(void) {
    TEST_RUN(empty_expression_accepts_everything);
    TEST_RUN(tcp_matches_only_tcp_over_ipv4);
    TEST_RUN(port_matches_either_direction_on_tcp_or_udp);
    TEST_RUN(host_and_net_match_ip_addresses);
    TEST_RUN(boolean_combinators_compose);
    TEST_RUN(compile_error_cases_report_failure);
    TEST_MAIN_END();
}
