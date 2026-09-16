#ifndef BPF_INTERP_H
#define BPF_INTERP_H

#include <linux/filter.h>
#include <stdint.h>

/*
Крошечный интерпретатор классического BPF, только для тестов.

Зачем он нужен, а не просто SO_ATTACH_FILTER в реальный сокет: тесты должны
работать без root/CAP_NET_RAW и без живого сетевого интерфейса (см. CI:
asan-ubsan job гоняет ctest без каких-либо привилегий). Интерпретируя
байт-код руками по тем же правилам, что и ядро (см. Documentation/networking/
filter.rst), можно проверить codegen на синтетических кадрах полностью
изолированно от ядра — и заодно ещё раз "прочитать" то, что генерирует
capfilter_compile, глазами независимой реализации.

Поддерживает ровно то подмножество опкодов, что умеет генерировать
capfilter.c: LD/LDX (W/H/B, ABS/IND/MSH), ALU AND K, JMP JEQ K, RET K.
*/

/* Возвращает то же, что вернула бы программа в ядре: 0 = пакет отбрасывается,
   >0 = пакет принимается (значение - "сколько байт пропустить наверх",
   нам достаточно знать факт accept/reject). */
uint32_t bpf_interp_run(const struct sock_fprog* prog, const uint8_t* pkt, uint32_t pkt_len);

#endif
