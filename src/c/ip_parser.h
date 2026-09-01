#ifndef IP_PARSER_H
#define IP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

   /*
Указатель eth_payload теперь смотрит на первый байт
IP-заголовка. ip_parser — второй слой разбора:
он вытаскивает адреса отправителя/получателя, TTL,
номер вложенного протокола (TCP? UDP? ICMP?) и
говорит следующему парсеру, где начинается его заголовок.

Без него ты бы знал только MAC-адреса — то есть
«какая железка на проводе передала кадр», но не «с
какого хоста на какой хост идёт пакет»
   */

#define IP_ADDR_LEN 4  // IPv4-адрес = 4 байта
#define IP_HEADER_MIN_LEN 20 // минимальный заголовок без опций

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

typedef struct {
    uint8_t version;        // 4 для IPv4
    uint8_t ihl;            // длина заголовка в 32-битных словах (5..15) */
    uint8_t tos;            // Type of Service / приоритет
    uint16_t total_length;  // весь пакет (заголовок + данные), байт
    uint16_t identification;// ID для сборки фрагментов
    uint8_t flags;          /* top 3 bits of the flags/fragment field */
    uint16_t fragment_offset;// смещение этого фрагмента
    uint8_t ttl;              // Time To Live — сколько ещё роутеров пройдёт
    uint8_t protocol;         // 6=TCP, 17=UDP, 1=ICMP
    uint16_t checksum;          // контрольная сумма заголовка из пакета
    uint8_t src_addr[IP_ADDR_LEN]; // IP отправителя
    uint8_t dst_addr[IP_ADDR_LEN];  // IP получателя
    uint8_t checksum_valid; /* 1 if the header checksum is correct, 0 otherwise */
} ip_header_t;

int ip_parse(const uint8_t* data, uint32_t length, ip_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
formats an IPv4 address as "a.b.c.d" into 'output', which must be at least
IP_ADDR_STR_LEN bytes long.
*/
#define IP_ADDR_STR_LEN 16
void ip_addr_to_str(const uint8_t addr[IP_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
