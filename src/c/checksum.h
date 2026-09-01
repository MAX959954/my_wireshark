#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

/*
Один маленький файл, реализующий интернет-контрольную сумму
(RFC 1071) — тот самый алгоритм, которым
проверяются на целостность заголовок IPv4, сегмент TCP и датаграмма
UDP.

Контрольная сумма нужна, чтобы поймать случайную порчу битов
(шум на линии, битая память роутера).
Требования: считаться быстро, на любом железе, инкрементально пересчитываться при изменении одного
поля (роутер уменьшает TTL — не пересчитывать же всё заново).

Один алгоритм на три протокола. IPv4, TCP, UDP
используют одну и ту же интернет-чексумму — код
написан один раз.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*
принимает предыдущую сумму, возвращает новую — можно вызывать цепочкой;
не сворачивает перенос — это делается один раз в конце;
нечётный хвостовой байт дополняется нулём справа.
*/
uint32_t checksum_partial(const uint8_t* data, uint32_t len, uint32_t sum);

/*
verifies the checksum already present inside 'data' - the checksum field
does not need to be zeroed first. Returns 1 if correct, 0 otherwise.
*/
int checksum_verify(const uint8_t* data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
