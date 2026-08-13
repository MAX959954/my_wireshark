#include "capture.h"

#include <pcap.h>
#include <stdio.h>
#include <string.h>

int capture_list_device(capture_device_t* output, int max_device) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return -1;
    }

    int count = 0;
    for (pcap_if_t* i = alldevs; i != NULL && count < max_device; i = i->next) {
        strncpy(output[count].name, i->name, CAPTURE_NAME_LEN - 1);
        output[count].name[CAPTURE_NAME_LEN - 1] = '\0';

        const char* desc = i->description ? i->description : "(no description)";
        strncpy(output[count].description, desc, CAPTURE_NAME_LEN - 1);
        output[count].description[CAPTURE_NAME_LEN - 1] = '\0';

        count++;
    }

    pcap_freealldevs(alldevs);
    return count;
}

struct capture_ctx {
    capture_packet_cb cb;
    void* user_data;
};

static void dispatch_trampoline(u_char* user, const struct pcap_pkthdr* header,
    const u_char* bytes) {
    struct capture_ctx* ctx = (struct capture_ctx*)user;
    ctx->cb(bytes, header->caplen, (uint32_t)header->ts.tv_sec,
        (uint32_t)header->ts.tv_usec, ctx->user_data);
}

int capture_run(const char* device_name, capture_packet_cb cb, void* user_data) {
    char errbuf[PCAP_ERRBUF_SIZE];

    /* snaplen 65536: capture full packets, not just headers.
       promisc 1: see traffic not addressed to this host too.
       timeout 1000ms: how long pcap_loop may buffer before delivering. */
    pcap_t* handle = pcap_open_live(device_name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

    struct capture_ctx ctx = { cb, user_data };
    int result = pcap_loop(handle, -1, dispatch_trampoline, (u_char*)&ctx);

    pcap_close(handle);
    return (result == -1) ? -1 : 0;
}