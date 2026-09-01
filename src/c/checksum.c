#include "checksum.h"

uint32_t checksum_partial(const uint8_t* data, uint32_t len, uint32_t sum) {
    uint32_t i = 0;

    for (; i + 1 < len; i += 2) {
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += (uint32_t)(data[i] << 8);
    }

    return sum;
}

/*
out_header->checksum_valid = (uint8_t)checksum_verify(data, header_len);
data — начало IPv4-заголовка, header_len = ihl * 4 (только заголовок,
без данных — IPv4-чексумма покрывает лишь заголовок). Поле checksum
на смещении 10–11 складывается вместе со всем. Если роутер по пути
побил, скажем, байт TTL и не пересчитал сумму (или пересчитал неверно)
— checksum_verify вернёт 0, и packet.cpp:33 допишет ip_csum=BAD
*/

int checksum_verify(const uint8_t* data, uint32_t len) {
    uint32_t sum = checksum_partial(data, len, 0);

    /*
    sum >> 16 — верхние 16 бит (накопленный перенос).
    sum & 0xFFFF — нижние 16 бит.
    Складываем их. Это и есть «обратный перенос» one's complement арифметики.
    while, а не if: само сложение может дать новый перенос (0xFFFF + 0x0001 = 0x10000). На практике
    хватает двух итераций, но цикл корректен для любого случая.
    */

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (sum & 0xFFFF) == 0xFFFF;
}
