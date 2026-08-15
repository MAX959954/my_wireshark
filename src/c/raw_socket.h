#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAW_SOCKET_MAX_DEVICES 32
#define RAW_SOCKET_NAME_LEN 256
#define RAW_SOCKET_MAX_FRAME 65536

typedef struct {
    char name[RAW_SOCKET_NAME_LEN];
} raw_socket_device_t;

/*
перечисляет сетевые интерфейсы через getifaddrs(), без дублей по имени.
Возвращает количество записей, записанных в 'output' (<= max_device),
или -1 при ошибке. Прав администратора не требует.
*/
int raw_socket_list_devices(raw_socket_device_t* output, int max_devices);

typedef struct raw_socket_ctx raw_socket_ctx_t;

/*
открывает AF_PACKET/SOCK_RAW/ETH_P_ALL сокет, привязанный к 'device_name'
через SO_BINDTODEVICE, и по возможности включает promiscuous-режим.
Требует CAP_NET_RAW (root или setcap). Возвращает NULL при ошибке
(с сообщением через perror).
*/
raw_socket_ctx_t* raw_socket_open(const char* device_name);

/*
блокирующий приём одного полного Ethernet-кадра (включая 14-байтный
L2-заголовок) в 'buf'. Возвращает >0 — число принятых байт (плюс
заполняет 'out_ts_seconds'/'out_ts_microseconds'), 0 — была запрошена
остановка (чистое завершение), -1 — ошибка (errno выставлен, perror
уже вызван).
*/
int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len,
    uint32_t* out_ts_seconds, uint32_t* out_ts_microseconds);

/*
потокобезопасно (atomic). Вызов из любого потока заставит блокирующий
raw_socket_recv() на этом 'ctx' вернуть 0 в течение ~200мс.
*/
void raw_socket_request_stop(raw_socket_ctx_t* ctx);

void raw_socket_close(raw_socket_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
