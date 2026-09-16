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

// Отдельный код возврата raw_socket_recv() для "запрошена остановка" —
// не пересекается с длиной кадра (>= 0, 0 — валидный нулевой кадр) и с -1 (ошибка)
#define RAW_SOCKET_STOPPED (-2)

//принять один кадр (блокирующе).
// Возврат: >= 0 — длина кадра в байтах (0 — легитимный нулевой кадр,
// не признак остановки); -1 — ошибка recv(); RAW_SOCKET_STOPPED —
// запрошена остановка через raw_socket_request_stop().
int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len,
    uint32_t* out_ts_seconds, uint32_t* out_ts_microseconds);

/*
Прицепить скомпилированную BPF-программу (см. capfilter.h) к сокету через
SO_ATTACH_FILTER. Дальше ядро отбрасывает ненужные пакеты само, ещё до
того, как raw_socket_recv() их увидит — фильтрация в ядре, не в
пользовательском пространстве. 'prog' не сохраняется (setsockopt копирует
программу в ядро), можно освобождать через capfilter_free() сразу после
вызова. Возвращает 0/-1; сама структура (linux/filter.h) сюда не
подключается, чтобы raw_socket.h не тянул за собой BPF-детали для тех, кто
не фильтрует.
*/
struct sock_fprog;
int raw_socket_attach_filter(raw_socket_ctx_t* ctx, const struct sock_fprog* prog);

//попросить recv завершиться (из другого потока/сигнала)
void raw_socket_request_stop(raw_socket_ctx_t* ctx);

//закрыть + освободить
void raw_socket_close(raw_socket_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
