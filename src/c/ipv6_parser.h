#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPV6_ADDR_LEN    16
#define IPV6_HEADER_LEN  40

    typedef struct {
        uint8_t  version;        /* always 6 */
        uint8_t  traffic_class;
        uint32_t flow_label;     /* low 20 bits significant */
        uint16_t payload_length;
        uint8_t  next_header;
        uint8_t  hop_limit;
        uint8_t  src_addr[IPV6_ADDR_LEN];
        uint8_t  dst_addr[IPV6_ADDR_LEN];
    } ipv6_header_t;
     
    /*
    анализирует сырой пакет IPv6, начинающийся с 'data'. При успешном заполнении
    'out_header', указывает 'out_payload' на байт прямо после (фиксированного
    размера IPV6_HEADER_LEN) IPv6-заголовка, а 'out_payload_len' на оставшуюся
    длину, затем возвращает 0. Возвращает -1, если 'length' короче
    IPV6_HEADER_LEN или версия не 6.
    */
    int ipv6_parse(const uint8_t* data, uint32_t length, ipv6_header_t* out_header,
        const uint8_t** out_payload, uint32_t* out_payload_len);

    /*
    формирует IPv6-адрес в стандартной записи "xxxx:xxxx:...:xxxx" в 'output',
    который должен быть длиной как минимум IPV6_ADDR_STR_LEN байт.
    */
#define IPV6_ADDR_STR_LEN 40
    void ipv6_addr_to_str(const uint8_t addr[IPV6_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
