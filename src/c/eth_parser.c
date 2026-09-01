#include "eth_parser.h"
#include <stdio.h>
#include <string.h>

int eth_parse(const uint8_t* data, uint32_t length, eth_header_t* out_header,
    const uint8_t** out_payload, uint32_t* out_payload_len) {

    /*
    * Проверка границ до любого чтения. length < 14 — кадр обрезан (усечённый захват),
    читать заголовок нельзя, иначе выход за буфер.
    */
    if (data == NULL || out_header == NULL || length < ETH_HEADER_LEN) {
        return -1;
    }

    //MAC-адреса копируются как есть — это просто 6 байт, порядок байт не важен.
    memcpy(out_header->dst_mac, data, ETH_ADDR_LEN);
    memcpy(out_header->src_mac, data + ETH_ADDR_LEN, ETH_ADDR_LEN);

    //MAC-адреса копируются как есть — это просто 6 байт, порядок байт не важен
    uint16_t type_or_tpid = (uint16_t)((data[12] << 8 ) | data[13]);
    uint32_t header_len = ETH_HEADER_LEN;

    //Пока неясно, это EtherType или TPID VLAN — отсюда имя переменной
    if (type_or_tpid == ETH_TYPE_VLAN) {  // 0x8100 → есть VLAN-тег
        if (length < ETH_HEADER_LEN + ETH_VLAN_TAG_LEN) { // нужно ещё 4 байта
            return -1;
        }

        out_header->has_vlan = 1;
        // TCI
        out_header->vlan_tci = (uint16_t)((data[14] << 8) | data[15]);
        // настоящий тип за тегом
        out_header->ether_type = (uint16_t)((data[16] << 8) | data[17]);
        // теперь 18
        header_len += ETH_VLAN_TAG_LEN;
    }
    else {
        out_header->has_vlan = 0;
        out_header->vlan_tci = 0;
        //// тега нет — это и был EtherType
        out_header->ether_type = type_or_tpid;
    }

    if (out_payload != NULL) {
        *out_payload = data + header_len;
    }

    if (out_payload_len != NULL) {
        *out_payload_len = length - header_len;
    }

    return 0;
}

void eth_mac_to_str(const uint8_t mac[ETH_ADDR_LEN], char* output) {
    snprintf(output, ETH_MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
