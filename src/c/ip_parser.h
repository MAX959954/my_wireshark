#ifndef IP_PARSER_H
#define IP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IP_ADDR_LEN 4
#define IP_HEADER_MIN_LEN 20

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

typedef struct {
    uint8_t version;
    uint8_t ihl;            /* header length in 32-bit words (5..15) */
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags;          /* top 3 bits of the flags/fragment field */
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_addr[IP_ADDR_LEN];
    uint8_t dst_addr[IP_ADDR_LEN];
} ip_header_t;

/*
анализирует сырой пакет IPv4, начинающийся с 'data'. При успешном заполнении
'out_header', указывает 'out_payload' на байт прямо после (переменной длины,
с учётом опций) IP-заголовка, а 'out_payload_len' на оставшуюся длину, затем
возвращает 0. Возвращает -1, если 'length' слишком короткая, версия не 4,
или IHL сообщает о заголовке короче IP_HEADER_MIN_LEN либо длиннее 'length'.
*/
int ip_parse(const uint8_t* data, uint32_t length, ip_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
формирует IPv4-адрес как "a.b.c.d" в 'output', который должен быть длиной
как минимум IP_ADDR_STR_LEN байт.
*/
#define IP_ADDR_STR_LEN 16
void ip_addr_to_str(const uint8_t addr[IP_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
