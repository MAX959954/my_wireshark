#ifndef ETH_PARSER_H
#define ETH_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_ADDR_LEN 6
#define ETH_HEADER_LEN 14

// ether types
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV6 0x86DD
#define ETH_TYPE_VLAN 0x8100

typedef struct {
    uint8_t dst_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ether_type;
} eth_header_t;

/*
анализирует исходный кадр Ethernet II, начинающийся с 'data'.
При успешном заполнении 'out_header', указывает 'out_payload'
на байт прямо после 14-байтного заголовка, а 'out_payload_len'
на оставшуюся длину, затем возвращает 0. Возвращает -1, если 'length'
слишком короткий для полного заголовка.
*/
int eth_parse(const uint8_t* data, uint32_t length, eth_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len);

/*
формирует MAC-адрес как "xx:xx:xx:xx:xx:xx" в 'output', который должен
быть длиной как минимум ETH_MAC_STR_LEN байт.
*/
#define ETH_MAC_STR_LEN 18
void eth_mac_to_str(const uint8_t mac[ETH_ADDR_LEN], char* output);

#ifdef __cplusplus
}
#endif

#endif
