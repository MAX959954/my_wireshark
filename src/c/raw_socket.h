#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
источник данных, самый низ стека (L1/L2 граница): он просит у
ядра Linux копию каждого кадра,
который проходит через сетевую карту, и отдаёт наверх сырой
буфер + метку времени.

Дальше по цепочке: raw_socket → capture_backend_linux (обёртка
+ запись в .pcap) → main.cpp →
парсеры.

*/

/*
 Обычный сокет (AF_INET) даёт тебе только
 payload твоих собственных соединений — ядро уже сняло
 Ethernet/IP/TCP.

 socket(AF_PACKET, SOCK_RAW, ETH_P_ALL) — особый сокет Linux:

AF_PACKET — работаем на канальном уровне (L2)
SOCK_RAW — отдавай кадр целиком, включая Ethernet-заголовок
ETH_P_ALL — все протоколы, весь трафик, не только адресованный нам

Это ровно то, что нужно снифферу. Требует привилегии
CAP_NET_RAW (root или setcap cap_net_raw+ep),
потому что позволяет читать чужой трафик
*/

#define RAW_SOCKET_MAX_DEVICES 32 // максимум интерфейсов в списке
#define RAW_SOCKET_NAME_LEN 256 // макс. длина имени интерфейса ("eth0", "wlan0"...)
#define RAW_SOCKET_MAX_FRAME 65536 // макс. размер кадра (буфер под один пакет)

typedef struct {
    char name[RAW_SOCKET_NAME_LEN];// просто имя интерфейса
} raw_socket_device_t;

//перечислить интерфейсы
int raw_socket_list_devices(raw_socket_device_t* output, int max_devices);

typedef struct raw_socket_ctx raw_socket_ctx_t;

// открыть сокет на интерфейсе
raw_socket_ctx_t* raw_socket_open(const char* device_name);

//принять один кадр (блокирующе)
int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len,
    uint32_t* out_ts_seconds, uint32_t* out_ts_microseconds);

//попросить recv завершиться (из другого потока/сигнала)
void raw_socket_request_stop(raw_socket_ctx_t* ctx);

//закрыть + освободить
void raw_socket_close(raw_socket_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
