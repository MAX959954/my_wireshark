#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <stdint.h>

/*
Проблема: компьютер знает, что хочет отправить пакет на 192.168.1.5,
но физически кадр в Ethernet доставляется не по IP, а по MAC-адресу.
MAC соседа он не знает.

Решение — ARP:

Хост кричит на всю подсеть (броадкаст): «у кого 192.168.1.5?
скажите свой MAC» — это request.
Владелец отвечает лично: «это я, мой MAC aa:bb:cc:...» — это reply.
Хост запоминает пару в ARP-кэше и дальше шлёт кадры прямо на этот MAC.

*/

#ifdef __cplusplus
extern "C" {
#endif

    /* Only the Ethernet/IPv4 case (hw_addr_len=6, proto_addr_len=4) is modeled;
       that covers effectively all ARP traffic seen on real networks. */

#define ARP_HEADER_LEN 28 //Размер ARP - заголовка для случая Ethernet + IPv4

#define ARP_HTYPE_ETHERNET 1 //какая канальная технология используеться
/*
Значение	Технология
1	        Ethernet
6	        IEEE 802 (Token Ring и пр.)
15	        Frame Relay
16	        ATM
20	        Serial Line
*/

#define ARP_PTYPE_IPV4     0x0800 //для какого протокола сетевого уровня мы резолвим адрес
/*
Значение	Протокол
0x0800	    IPv4
0x86DD	    IPv6
0x0806	    ARP (сам)
*/

#define ARP_OP_REQUEST 1 //что это за сообщение
#define ARP_OP_REPLY 2
/*
Значение	Смысл
1	        request — «у кого IP X? сообщите свой MAC» (обычно броадкаст)
2	        reply — «IP X у меня, вот мой MAC» (юникаст отправителю)
3	        RARP request
4	        RARP reply
*/

    typedef struct {
        uint16_t hardware_type; //2 byte 
        uint16_t protocol_type; //2 
        uint8_t  hardware_addr_len; //1
        uint8_t  protocol_addr_len; //1
        uint16_t opcode; //2
        uint8_t  sender_mac[6]; //6
        uint8_t  sender_ip[4]; // 4 
        uint8_t  target_mac[6]; //6 
        uint8_t  target_ip[4]; //4
    } arp_header_t; //28  

    int arp_parse(const uint8_t* data, uint32_t length, arp_header_t* out_header);

#ifdef __cplusplus
}
#endif
#endif
