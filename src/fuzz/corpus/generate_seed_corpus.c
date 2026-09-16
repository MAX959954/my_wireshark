/* One-shot tool that writes the seed corpus files under src/fuzz/corpus/.
   Not part of the build (see CMakeLists.txt) - run manually if the corpus
   needs regenerating:

     gcc -std=c11 -o /tmp/gen generate_seed_corpus.c && cd .. && /tmp/gen

   Seeds are deliberately tiny, hand-built valid/near-valid frames: a
   fuzzer mutates from here far more effectively than from nothing, since
   it starts already past the length/magic-number checks parsers reject
   first. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void write_file(const char* path, const uint8_t* data, size_t len) {
    FILE* f = fopen(path, "wb");
    if (f == NULL) { perror(path); return; }
    if (len > 0) {
        fwrite(data, 1, len, f);
    }
    fclose(f);
    printf("wrote %s (%zu bytes)\n", path, len);
}

int main(void) {
    /* ---- eth: 14-byte header + EtherType ---- */
    {
        uint8_t ipv4_frame[34] = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, /* dst mac */
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* src mac */
            0x08, 0x00,                          /* EtherType = IPv4 */
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0,
            192, 168, 1, 10, 93, 184, 216, 34,
        };
        write_file("eth/ipv4_frame.bin", ipv4_frame, sizeof(ipv4_frame));

        uint8_t vlan_frame[38] = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x81, 0x00, 0x00, 0x64,             /* VLAN tag, VID=100 */
            0x08, 0x00,                          /* inner EtherType = IPv4 */
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0,
            192, 168, 1, 10, 93, 184, 216, 34,
        };
        write_file("eth/vlan_frame.bin", vlan_frame, sizeof(vlan_frame));

        uint8_t truncated[5] = { 0x11, 0x22, 0x33, 0x44, 0x55 };
        write_file("eth/truncated.bin", truncated, sizeof(truncated));

        write_file("eth/empty.bin", NULL, 0);
    }

    /* ---- arp: 28-byte Ethernet/IPv4 ARP request ---- */
    {
        uint8_t req[28] = {
            0x00, 0x01,             /* hardware = Ethernet */
            0x08, 0x00,             /* protocol = IPv4 */
            6, 4,                    /* hw len, proto len */
            0x00, 0x01,               /* opcode = request */
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* sender mac */
            192, 168, 1, 1,                       /* sender ip */
            0, 0, 0, 0, 0, 0,                       /* target mac (unknown) */
            192, 168, 1, 2,                          /* target ip */
        };
        write_file("arp/request.bin", req, sizeof(req));

        uint8_t truncated[10];
        memcpy(truncated, req, sizeof(truncated));
        write_file("arp/truncated.bin", truncated, sizeof(truncated));

        write_file("arp/empty.bin", NULL, 0);
    }

    /* ---- ip: 20-byte IPv4 header, and one with a 4-byte options word ---- */
    {
        uint8_t hdr[20] = {
            0x45, 0x00, 0x00, 0x28, 0xab, 0x12, 0x00, 0x00, 0x40, 0x06,
            0xd8, 0x30, 192, 168, 1, 10, 93, 184, 216, 34,
        };
        write_file("ip/basic.bin", hdr, sizeof(hdr));

        uint8_t with_options[24] = {
            0x46, 0x00, 0x00, 0x2c, 0xab, 0x12, 0x00, 0x00, 0x40, 0x06,
            0xd8, 0x30, 192, 168, 1, 10, 93, 184, 216, 34,
            0x01, 0x01, 0x01, 0x00, /* NOP NOP NOP EOL padding as fake options */
        };
        write_file("ip/with_options.bin", with_options, sizeof(with_options));

        uint8_t truncated[10];
        memcpy(truncated, hdr, sizeof(truncated));
        write_file("ip/truncated.bin", truncated, sizeof(truncated));

        write_file("ip/empty.bin", NULL, 0);
    }

    /* ---- ipv6: 40-byte header ---- */
    {
        uint8_t hdr[40] = {
            0x60, 0x00, 0x00, 0x00,     /* version=6, traffic class=0, flow=0 */
            0x00, 0x14,                   /* payload length = 20 */
            0x06,                          /* next header = TCP */
            0x40,                            /* hop limit = 64 */
            /* src addr: 2001:db8::1 */
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            /* dst addr: 2001:db8::2 */
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        };
        write_file("ipv6/basic.bin", hdr, sizeof(hdr));

        uint8_t truncated[15];
        memcpy(truncated, hdr, sizeof(truncated));
        write_file("ipv6/truncated.bin", truncated, sizeof(truncated));

        write_file("ipv6/empty.bin", NULL, 0);
    }

    /* ---- tcp_udp: 20-byte TCP header and 8-byte UDP header ---- */
    {
        uint8_t tcp_hdr[20] = {
            0x1f, 0x90, 0x00, 0x50,        /* src=8080 dst=80 */
            0x00, 0x00, 0x00, 0x01,          /* seq */
            0x00, 0x00, 0x00, 0x00,           /* ack */
            0x50, 0x02,                        /* data_offset=5, flags=SYN */
            0xff, 0xff, 0x00, 0x00, 0x00, 0x00,  /* window, checksum, urgent */
        };
        write_file("tcp_udp/tcp_basic.bin", tcp_hdr, sizeof(tcp_hdr));

        uint8_t udp_hdr[8] = { 0x00, 0x35, 0x1f, 0x90, 0x00, 0x08, 0x00, 0x00 };
        write_file("tcp_udp/udp_basic.bin", udp_hdr, sizeof(udp_hdr));

        uint8_t truncated[6];
        memcpy(truncated, tcp_hdr, sizeof(truncated));
        write_file("tcp_udp/truncated.bin", truncated, sizeof(truncated));

        write_file("tcp_udp/empty.bin", NULL, 0);
    }

    return 0;
}
