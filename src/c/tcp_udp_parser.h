#ifndef TCP_UDP_PARSER_H
#define TCP_UDP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TCP_HEADER_MIN_LEN 20
#define UDP_HEADER_LEN 8

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

/*
анализирует сырой сегмент TCP, начинающийся с 'data'. При успешном заполнении
'out_header', указывает 'out_payload' на байт прямо после (переменной длины)
TCP-заголовка, а 'out_payload_len' на оставшуюся длину, затем возвращает 0.
Возвращает -1, если 'length' слишком короткая или заголовок сообщает
о неверном смещении данных.
*/
int tcp_parse(const uint8_t* data, uint32_t length, tcp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
анализирует сырой сегмент UDP, начинающийся с 'data'. При успешном заполнении
'out_header', указывает 'out_payload' на байт прямо после 8-байтного заголовка,
а 'out_payload_len' на оставшуюся длину, затем возвращает 0. Возвращает -1,
если 'length' меньше UDP_HEADER_LEN.
*/
int udp_parse(const uint8_t* data, uint32_t length, udp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

#ifdef __cplusplus
}
#endif

#endif
