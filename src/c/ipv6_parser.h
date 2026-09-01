#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
IPv6 придуман потому, что 4-байтовых адресов IPv4 (≈4 млрд)
на планету не хватило. В IPv6 адрес — 16
байт (2¹²⁸ штук). Заодно упростили заголовок.
*/

#define IPV6_ADDR_LEN    16 // адрес 16 байт
#define IPV6_HEADER_LEN  40  // заголовок всегда 40 байт (константа, не переменная!)

    typedef struct {
        uint8_t  version;        /* always 6 */
        uint8_t  traffic_class;  // приоритет/QoS — аналог TOS в IPv4
        uint32_t flow_label;     /* low 20 bits significant */
        uint16_t payload_length; // длина ТОЛЬКО данных после заголовка (не весь пакет!)
        uint8_t  next_header;    // что дальше: 6=TCP, 17=UDP, 58=ICMPv6, 0/43/44=ext.header
        uint8_t  hop_limit;      // сколько роутеров ещё пройдёт (было "TTL")   
        uint8_t  src_addr[IPV6_ADDR_LEN];
        uint8_t  dst_addr[IPV6_ADDR_LEN];
    } ipv6_header_t;
     
   
    int ipv6_parse(const uint8_t* data, uint32_t length, ipv6_header_t* out_header,
        const uint8_t** out_payload, uint32_t* out_payload_len);

    /*
    formats an IPv6 address in standard "xxxx:xxxx:...:xxxx" notation into
    'output', which must be at least IPV6_ADDR_STR_LEN bytes long.
    */
#define IPV6_ADDR_STR_LEN 40
    void ipv6_addr_to_str(const uint8_t addr[IPV6_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
