#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
добавляет 'data' (длиной 'len' байт, в сетевом порядке) к незавершённой сумме
'sum' в дополнительном коде (RFC 1071). Нечётный последний байт дополняется
нулём справа. Возвращает обновлённую, ещё не свёрнутую сумму — так несколько
кусков (например, pseudo-header и сам сегмент) можно просуммировать по очереди
перед одной финальной сверткой.
*/
uint32_t checksum_partial(const uint8_t* data, uint32_t len, uint32_t sum);

/*
проверяет корректность чек-суммы, уже присутствующей внутри 'data' (длиной
'len' байт) — поле checksum обнулять не нужно. Возвращает 1, если чек-сумма
верна, иначе 0.
*/
int checksum_verify(const uint8_t* data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
