#ifndef ETH_PARSER_H
#define ETH_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*
    *Когда ты захватываешь трафик через raw-сокет (AF_PACKET),
    ОС отдаёт тебе кадр целиком, начиная с канального уровня —
    то есть первое, что лежит в буфере, это Ethernet-заголовок.
    Любой пакет (IPv4, IPv6, ARP) идёт внутри Ethernet-кадра как
    его полезная нагрузка.

    Значит, чтобы добраться до IP или ARP, надо сначала снять «конверт»
    Ethernet: понять, где он кончается и что за протокол лежит внутри
    Без него ни один из остальных парсеров не знал бы, с какого байта
    начинается его заголовок.
    * 
    */
   

#define ETH_ADDR_LEN 6 //длина MAC-адреса в байтах
#define ETH_HEADER_LEN 14 //размер заголовка без VLAN (6+6+2)
#define ETH_VLAN_TAG_LEN 4 //	размер вставного VLAN-тега

// ether types
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV6 0x86DD

//это не тип, а маркер «дальше VLAN-тег»
#define ETH_TYPE_VLAN 0x8100

typedef struct {
    uint8_t dst_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ether_type;  // ЧТО внутри — уже "настоящий" тип, VLAN снят
    uint8_t has_vlan; // был ли VLAN-тег (0/1)
    uint16_t vlan_tci; // Tag Control Information, если has_vlan
} eth_header_t;

/*
VLAN (802.1Q) — способ гонять несколько логически разных
Для этого в Ethernet-кадр вставляется 4-байтовый тег:
сетей по одному физическому кабелю.

| TPID (2 байта) | TCI (2 байта) |
|    0x8100      |  PCP DEI VID  |

TPID = 0x8100 — маркер «здесь VLAN-тег» (в коде это ETH_TYPE_VLAN).
TCI (Tag Control Information) — 16 бит, набитые тремя полями:

 бит:  15 14 13 | 12 | 11 10 9 8 7 6 5 4 3 2 1 0
       PCP      |DEI |        VID (VLAN ID)
       3 бита   | 1  |        12 бит

Поле	Биты	Значение	Зачем
PCP	    15–13	0–7	        Priority Code Point — приоритет трафика (QoS). 0 = обычный,
7 = сетевое управление

DEI	    12	    0/1     	Drop Eligible — можно ли дропнуть кадр при перегрузке

VID	    11–0	0–4095	    номер VLAN — к какой виртуальной сети относится кадр
*/


/*
VID сидит в младших 12 битах. 0x0FFF в двоичном виде:

0000 1111 1111 1111

Операция & (побитовое И) оставляет бит только там, где в маске стоит 1:

  tci   = 1010 0110 0100 0001   (PCP=101, DEI=0, VID=0110 0100 0001)
& 0x0FFF= 0000 1111 1111 1111
--------------------------------
  =       0000 0110 0100 0001   = VID = 1601

  Старшие 4 бита (PCP + DEI) обнуляются — остаётся чистый номер VLAN
*/

#define ETH_VLAN_ID(tci) ((tci) & 0x0FFF)


/*
PCP сидит в старших 3 битах (позиции 15, 14, 13). >> 13 сдвигает всё число на 13 позиций вправо —
биты 15–13 «съезжают» в позиции 2–0, всё остальное выпадает за край и теряется:

  tci      = 1010 0110 0100 0001
  tci >> 13= 0000 0000 0000 0101   = PCP = 5

Маска здесь не нужна: биты справа от PCP просто вытолкнуты. (uint8_t) — приведение к байту, т.к.
результат гарантированно 0–7, и чтобы тип совпадал с полем в структуре.
*/

#define ETH_VLAN_PCP(tci) ((uint8_t)((tci) >> 13))

/*
parses a raw Ethernet II frame starting at 'data'. On success, fills
'out_header', points 'out_payload' at the byte right after the 14-byte
header, and 'out_payload_len' at the remaining length, then returns 0.
Returns -1 if 'length' is too short for a full header.
*/
int eth_parse(const uint8_t* data, uint32_t length, eth_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
formats a MAC address as "xx:xx:xx:xx:xx:xx" into 'output', which must be
at least ETH_MAC_STR_LEN bytes long.
*/
#define ETH_MAC_STR_LEN 18
//Утилита форматирования MAC в строку — чисто для печати summary.
void eth_mac_to_str(const uint8_t mac[ETH_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
