#include  "arp_parser.h"
#include <stddef.h>
#include <string.h>

/*
Парсинг (разбор) — это процесс превращения «сырых» данных в
структуру, понятную человеку или программе. На вход подаётся
поток байт, на выходе — набор именованных полей со значениями
*/

int arp_parse(const uint8_t* data, uint32_t length, arp_header_t* out_header) {

    //После этой строки гарантировано: указатели валидны и в буфере есть
    // минимум 28 байт. Дальше можно читать data[0..27] без проверок. < а не !=
    if (data == NULL || out_header == NULL || length < ARP_HEADER_LEN) {
        return -1;
    }

    //чтение первых 6 байт заголовка для валидации — прежде
    // чем доверять остальному пакету. Потому что от них
    // зависит вся дальнейшая раскладка пакета

    /*
     Потому что 16-битное число лежит в пакете как два
     отдельных байта в порядке big-endian (network byte
     order), и надо собрать из них одно число, не полагаясь
     на то, как хранит числа конкретный процессор.
    */

    uint16_t htype = (uint16_t)((data[0] << 8) | data[1]);  //канальная технология. Должно быть 1 (Ethernet)
    uint16_t ptype = (uint16_t)((data[2] << 8) | data[3]);  //протокол L3. Должно быть 0x0800 (IPv4)

    //Здесь сдвига нет, потому что поле однобайтовое
    uint8_t hlen = data[4];  //длина аппаратного адреса. Должно быть 6 (MAC)
    uint8_t plen = data[5];  //длина протокольного адреса. Должно быть 4 (IPv4)

    if (htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen  != 6 || plen != 4) {
        return -1;
    }

    /*
    Это заполнение выходной структуры out_header — то,
    ради чего вызвали arp_parse. К этому моменту
    валидация уже пройдена, теперь просто переносим
    разобранные значения в результат, который увидит
    вызывающий код
    */
    out_header->hardware_type = htype;
    out_header->protocol_type = ptype;
    out_header->hardware_addr_len = hlen;
    out_header->protocol_addr_len = plen;

    out_header->opcode = (uint16_t)((data[6] << 8) | data[7]);

    //Раз формат подтверждён — можно безопасно копировать
    // адреса по фиксированным смещениям.
    memcpy(out_header->sender_mac, data + 8, 6);
    memcpy(out_header->sender_ip, data + 14, 4);
    memcpy(out_header->target_mac, data + 18, 6);
    memcpy(out_header->target_ip, data + 24, 4);
    return  0;
}
