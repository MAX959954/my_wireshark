#include "ip_parser.h"
#include "checksum.h"
#include <stddef.h>
#include <stdio.h>

int ip_parse(const uint8_t* data, uint32_t length, ip_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len) {


    //Проверка входа ,  length < 20 данных не хватает даже на минимальный заголовок. Читать нельзя — вернём ошибку.
    if (data == NULL || out_header == NULL || length < IP_HEADER_MIN_LEN) {
        return -1;
    }

    /*
    Один байт упаковывает два поля по 4 бита — та же техника, что с VLAN TCI:

    >> 4 сдвигает старший ниббл вниз → версия
    & 0x0F (0000 1111) оставляет младший ниббл → IHL
    */

    uint8_t version = data[0] >> 4; // старшие 4 бита 
    uint8_t ihl = data[0] & 0x0F; // младшие 4 бита
    uint32_t header_len = (uint32_t)ihl * 4; // переводим слова в байты

    //Это защита от порчи памяти на битых пакетах.
    if (version != 4 || ihl < 5 || header_len > length) {
        return -1;
    }

    out_header->checksum_valid = (uint8_t)checksum_verify(data, header_len);

    out_header->version = version;
    out_header->ihl = ihl;
    out_header->tos = data[1];

    /*
    total_length и identification — 16-битные, собираются вручную из двух байт (старший << 8,
    младший добавить). Сеть = big-endian, хост может быть любой — поэтому не читаем через uint16_t*,
    а складываем побайтово
    */
    out_header->total_length = (uint16_t)((data[2] << 8) | data[3]);
    out_header->identification = (uint16_t)((data[4] << 8) | data[5]);

    uint16_t flags_frag = (uint16_t)((data[6] << 8) | data[7]);

    /*
    >> 13 → три флаговых бита (R=0, DF=«не фрагментировать», MF=«будут ещё фрагменты»)
    & 0x1FFF (0001 1111 1111 1111) → смещение фрагмента
    */
    out_header->flags = (uint8_t)(flags_frag >> 13); // старшие 3 бита
    out_header->fragment_offset = flags_frag & 0x1FFF; // младшие 13 бит 

    out_header->ttl = data[8];
    out_header->protocol = data[9];
    out_header->checksum = (uint16_t)((data[10] << 8) | data[11]);

    //Адреса — по байту
    //IPv4-адрес хранится как 4 «сырых» байта;
    // в строку "a.b.c.d" он превращается только в ip_addr_to_str
    out_header->src_addr[0] = data[12];
    out_header->src_addr[1] = data[13];
    out_header->src_addr[2] = data[14];
    out_header->src_addr[3] = data[15];

    out_header->dst_addr[0] = data[16];
    out_header->dst_addr[1] = data[17];
    out_header->dst_addr[2] = data[18];
    out_header->dst_addr[3] = data[19];

    if (out_payload != NULL) {
        *out_payload = data + header_len;
    }


    /*
    Расхождение бывает из-за L2-паддинга: Ethernet требует минимум 60 байт кадра. Короткий пакет
    (голый TCP ACK без данных) добивается нулями до минимума. Эти нули физически есть в буфере, но к
    IP-пакету не относятся.

    Логика: берём меньшее из двух. total_length — авторитетный источник размера датаграммы, поэтому если
    он меньше — обрезаем «хвост» (паддинг). Но если total_length больше того, что захвачено (обрезанный
    захват, snaplen), — доверять ему нельзя, работаем с тем, что есть.

    Без этой поправки tcp_parse получил бы лишние байты паддинга, а проверка TCP-чексуммы поехала бы.
    */
    if (out_payload_len != NULL) {
        uint32_t available_payload_len = length - header_len; // сколько байт осталось в буфере

        if (out_header->total_length >= header_len) {
            uint32_t declared_payload_len = out_header->total_length - header_len; //сколько байт данных заявляет сам IP
            if (declared_payload_len < available_payload_len) {
                available_payload_len = declared_payload_len;
            }
        }

        *out_payload_len = available_payload_len;
    }

    return 0;
}

void ip_addr_to_str(const uint8_t addr[IP_ADDR_LEN], char* output) {
    snprintf(output, IP_ADDR_STR_LEN, "%u.%u.%u.%u",
        addr[0], addr[1], addr[2], addr[3]);
}
