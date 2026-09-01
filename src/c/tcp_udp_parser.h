#ifndef TCP_UDP_PARSER_H
#define TCP_UDP_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*
Это L4 — транспортный уровень. ip_parser дал адреса хостов и поле protocol.
По нему main.cpp зовёт
либо tcp_parse, либо udp_parse. Задача L4 — сказать, какому процессу на хосте адресован пакет
(порты), и — для TCP — в каком состоянии находится соединение (флаги, seq/ack).
    */

#define TCP_HEADER_MIN_LEN 20 // минимум без опций
#define UDP_HEADER_LEN 8  // всегда 8

//Флаги TCP — битовые маски

/*
Все 6 флагов лежат в одном байте (data[13]), каждый — свой бит.
Проверка: if (tcp.flags &
TCP_FLAG_SYN). Классическое начало соединения — SYN,
ответ — SYN|ACK (0x12), завершение — FIN|ACK.
*/
#define TCP_FLAG_FIN 0x01 // 0000 0001  — конец передачи, «я всё отправил»
#define TCP_FLAG_SYN 0x02 // 0000 0010  — начало соединения, синхронизация seq
#define TCP_FLAG_RST 0x04 // 0000 0100  — сброс, «соединения нет / ошибка»
#define TCP_FLAG_PSH 0x08 // 0000 1000  — отдать данные приложению немедленно
#define TCP_FLAG_ACK 0x10 // 0001 0000  — поле ack_num значимо (подтверждение)
#define TCP_FLAG_URG 0x20 // 0010 0000  — есть срочные данные (urgent_pointer)

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num; // номер первого байта в этом сегменте
    uint32_t ack_num; // «жду байт с этим номером» (если ACK взведён)
    uint8_t data_offset; // длина заголовка в 32-битных словах (5..15)
    uint8_t flags;   // 6 младших бит: URG ACK PSH RST SYN FIN
    uint16_t window_size;  // сколько байт готов принять (управление потоком)
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint8_t checksum_valid; /* filled in by tcp_verify_checksum(), not tcp_parse() */
} tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t checksum_present; /* 0 if checksum == 0 - sender chose not to compute it (RFC 768) */
    uint8_t checksum_valid;   /* filled in by udp_verify_checksum(), not udp_parse() */
} udp_header_t;


int tcp_parse(const uint8_t* data, uint32_t length, tcp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);


int udp_parse(const uint8_t* data, uint32_t length, udp_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);


int tcp_verify_checksum(const uint8_t* segment, uint32_t segment_len,
    const uint8_t src_ip[4], const uint8_t dst_ip[4]);


int udp_verify_checksum(const uint8_t* segment, uint32_t segment_len,
    const uint8_t src_ip[4], const uint8_t dst_ip[4]);

#ifdef __cplusplus
}
#endif

#endif
