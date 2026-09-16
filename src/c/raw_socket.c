#include "raw_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/*
PACKET_MMAP / TPACKET_V3 — zero-copy ring buffer capture.

Проблема с "один recv() на пакет": каждый вызов — это переход user/kernel,
а на кадр он один. При интересном pps (десятки-сотни тысяч пакетов в
секунду) это становится потолком: время уходит не на разбор пакетов, а на
сами syscall'ы и на копирование каждого кадра ядром в наш буфер по одному.

PACKET_MMAP решает это иначе: ядро и процесс мапят (mmap) один и тот же
кусок памяти — "кольцо" из последовательных "блоков" (block). Ядро само
складывает туда пришедшие кадры (без обращения к нам), а как только блок
заполнился или истёк tp_retire_blk_tov (наш прежний таймаут 200мс),
помечает его как готовый (TP_STATUS_USER) и, если мы спали в poll(),
будит нас. Мы читаем из готового блока сколько угодно кадров без единого
syscall на кадр, а когда блок вычитан — отдаём его обратно ядру
(TP_STATUS_KERNEL) одной записью в память. Копирование из блока в буфер
вызывающего (raw_socket_recv's 'buf') остаётся — так API этого модуля не
меняется для всех вызывающих (capture_backend_linux.c, тесты), — но
исчезает копирование "ядро -> сокет-буфер -> наш буфер" на КАЖДЫЙ пакет;
осталась только одна копия "ring -> buf", и ноль syscall'ов, пока в кольце
есть непрочитанные кадры.

TPACKET_V3 (а не V1/V2) выбран потому, что кадры в блоке идут вплотную
друг за другом переменной длины (через tp_next_offset), а не в
фиксированных слотах — меньше потерь места на padding, и ядро само решает,
когда закрыть блок (по заполнению или по таймауту), а не блокируется, пока
слот не освободится.
*/

#define RS_RING_BLOCK_SIZE (1u << 20) /* 1 MiB на блок; кратно странице и frame_size */
#define RS_RING_BLOCK_NR   8u          /* 8 блоков => 8 MiB кольцо суммарно */
#define RS_RING_FRAME_SIZE 2048u        /* используется только для расчёта tp_frame_nr */
#define RS_RING_RETIRE_TOV_MS 200u       /* как долго блок ждёт заполнения перед тем как закрыться пустым/частичным - та же гранулярность, что раньше давал SO_RCVTIMEO, чтобы Ctrl+C реагировал так же быстро */

struct raw_socket_ctx {
    int fd; // файловый дескриптор сокета
    atomic_int stop_requested;  // флаг остановки, атомарный
    char device_name[RAW_SOCKET_NAME_LEN]; // нужно, чтобы снять promiscuous при закрытии
    int promisc_set_by_us; // 1, если это мы включили IFF_PROMISC (и должны его снять)

    uint8_t* ring;      // mmap'нутая память кольца целиком (все блоки подряд)
    size_t ring_size;    // = block_size * block_nr, нужен для munmap
    unsigned int block_size;
    unsigned int block_nr;

    // Курсор чтения: какой блок сейчас читаем и сколько пакетов из него уже
    // отдали наверх. cur_pkt_idx == 0 означает "этот блок ещё не начат" -
    // тогда сначала проверяем его block_status, а не просто грузим следующий
    // пакет.
    unsigned int cur_block;
    unsigned int cur_pkt_idx;
    unsigned int cur_pkt_offset;  // байтовое смещение следующего tpacket3_hdr внутри блока
    unsigned int cur_num_pkts;    // сколько пакетов всего в текущем блоке (кэш bh1.num_pkts)
};

static uint8_t* rs_block_at(raw_socket_ctx_t* ctx, unsigned int index) {
    return ctx->ring + (size_t)index * ctx->block_size;
}

int raw_socket_list_devices(raw_socket_device_t* output, int max_devices) {
    if (output == NULL || max_devices == 0) {
        return -1;
    }

    //getifaddrs() — POSIX-функция, возвращает
    // связный список всех сетевых адресов системы. Не требует прав.
    struct ifaddrs* addr = NULL;
    if (getifaddrs(&addr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    int count = 0;
    for (struct ifaddrs* i = addr; i != NULL && count < max_devices; i = i->ifa_next) {
        if (i->ifa_name == NULL) {
            continue;
        }

        /*
        Проход по списку. Проблема: getifaddrs возвращает по записи на каждый адрес, а не на
        интерфейс. У eth0 может быть IPv4-адрес, IPv6-адрес, MAC — три записи с именем "eth0".
        Отсюда дедупликация
        */

        int duplicate = 0;
        for (int j = 0; j < count; j++) {
            if (strcmp(output[j].name, i->ifa_name) == 0){
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        //Линейный поиск по уже добавленным именам — O(n²), но n ≤ 32, неважно.
        strncpy(output[count].name, i->ifa_name, RAW_SOCKET_NAME_LEN - 1);
        output[count].name[RAW_SOCKET_NAME_LEN - 1] = '\0';
        count++;
    }

    freeifaddrs(addr);
    return count;
}


raw_socket_ctx_t* raw_socket_open(const char* device_name) {
    if (device_name == NULL) {
        return NULL;
    }

    //htons (host-to-network short) — третий аргумент должен быть
    // в сетевом порядке байт. ETH_P_ALL = 0x0003; на little-endian
    // машине без htons ядро получило бы 0x0300
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        perror("socket(AF_PACKET, SOCK_RAW)");
        return NULL;
    }

    //Привязать к одному интерфейсу
    /*
    Без этого сокет ловил бы трафик со всех интерфейсов сразу.
    SO_BINDTODEVICE ограничивает
    выбранным (eth0). + 1 — включаем \0 в длину.
    */
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device_name,
        (socklen_t)(strlen(device_name) + 1)) == -1) {
        perror("setsockopt(SO_BINDTODEVICE)");
        close(fd);
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device_name, IFNAMSIZ - 1);

    // прочитать текущие флаги интерфейса
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        perror("ioctl(SIOCGIFFLAGS)");
        close(fd);
        return NULL;
    }

    /*
    Promiscuous mode — «неразборчивый режим». Обычно сетевая карта
    отбрасывает кадры, где MAC
    назначения не её (и не broadcast/multicast). В promiscuous она
    отдаёт ядру всё, что физически
    услышала — весь трафик сегмента, включая чужой. Для сниффера
    критично.
    */

    int promisc_set_by_us = 0;
    if (!(ifr.ifr_flags & IFF_PROMISC)) {
        ifr.ifr_flags |= IFF_PROMISC; // добавить бит "promiscuous"
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) { // записать обратно
            perror("ioctl(SIOCSIFFLAGS) - promiscuous mode unavailable");
        } else {
            promisc_set_by_us = 1; // это мы включили — значит нам и выключать при close
        }
    }

    // TPACKET_V3: переключаем сокет с "обычного" AF_PACKET на режим
    // кольцевого буфера (см. большой комментарий про PACKET_MMAP выше).
    int tpacket_version = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &tpacket_version, sizeof(tpacket_version)) == -1) {
        perror("setsockopt(PACKET_VERSION, TPACKET_V3)");
        close(fd);
        return NULL;
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = RS_RING_BLOCK_SIZE;
    req.tp_frame_size = RS_RING_FRAME_SIZE;
    req.tp_block_nr = RS_RING_BLOCK_NR;
    req.tp_frame_nr = (RS_RING_BLOCK_SIZE / RS_RING_FRAME_SIZE) * RS_RING_BLOCK_NR;
    req.tp_retire_blk_tov = RS_RING_RETIRE_TOV_MS;

    // Просим ядро выделить и разметить кольцо под этот сокет. После этого
    // вызова каждый recv() был бы избыточен - кадры уже льются в кольцо.
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) == -1) {
        perror("setsockopt(PACKET_RX_RING)");
        close(fd);
        return NULL;
    }

    size_t ring_size = (size_t)req.tp_block_size * req.tp_block_nr;
    void* ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        perror("mmap(PACKET_RX_RING)");
        close(fd);
        return NULL;
    }

    //Выделить контекст
    raw_socket_ctx_t* ctx = malloc(sizeof(raw_socket_ctx_t));
    if (ctx == NULL) {
        perror("malloc");
        munmap(ring, ring_size);
        close(fd);
        return NULL;
    }

    ctx->fd = fd;
    atomic_init(&ctx->stop_requested, 0);
    strncpy(ctx->device_name, device_name, RAW_SOCKET_NAME_LEN - 1);
    ctx->device_name[RAW_SOCKET_NAME_LEN - 1] = '\0';
    ctx->promisc_set_by_us = promisc_set_by_us;
    ctx->ring = ring;
    ctx->ring_size = ring_size;
    ctx->block_size = req.tp_block_size;
    ctx->block_nr = req.tp_block_nr;
    ctx->cur_block = 0;
    ctx->cur_pkt_idx = 0;
    ctx->cur_pkt_offset = 0;
    ctx->cur_num_pkts = 0;
    return ctx;
}

int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len,
    uint32_t  * out_ts_seconds , uint32_t  * out_ts_microseconds ) {

    if (ctx == NULL || buf == NULL) {
        return -1;
    }

    for (;;) {
        if (atomic_load(&ctx->stop_requested)) {
            return RAW_SOCKET_STOPPED; // отдельный код — не путать с валидным нулевым кадром
        }

        struct tpacket_block_desc* bd = (struct tpacket_block_desc*)rs_block_at(ctx, ctx->cur_block);

        if (ctx->cur_pkt_idx == 0) {
            // Ещё не начинали читать этот блок - сначала убедиться, что он
            // вообще принадлежит нам (TP_STATUS_USER), а не всё ещё
            // заполняется ядром.
            if (!(bd->hdr.bh1.block_status & TP_STATUS_USER)) {
                // poll() вместо recv()-таймаута: спим, пока ядро либо не
                // закроет текущий блок (заполнением или по
                // tp_retire_blk_tov), либо не истечёт наш собственный
                // таймаут — тогда возвращаемся наверх и снова проверяем
                // stop_requested, как раньше делал EAGAIN каждые 200мс.
                struct pollfd pfd;
                pfd.fd = ctx->fd;
                pfd.events = POLLIN;
                pfd.revents = 0;
                int rc = poll(&pfd, 1, (int)RS_RING_RETIRE_TOV_MS);
                if (rc < 0 && errno != EINTR) {
                    perror("poll");
                    return -1;
                }
                continue;
            }

            ctx->cur_num_pkts = bd->hdr.bh1.num_pkts;
            ctx->cur_pkt_offset = bd->hdr.bh1.offset_to_first_pkt;

            if (ctx->cur_num_pkts == 0) {
                // Блок закрылся по таймауту без единого пакета (idle
                // interface) - вернуть его ядру и перейти к следующему.
                bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
                ctx->cur_block = (ctx->cur_block + 1) % ctx->block_nr;
                continue;
            }
        }

        struct tpacket3_hdr* hdr = (struct tpacket3_hdr*)((uint8_t*)bd + ctx->cur_pkt_offset);
        const uint8_t* frame = (const uint8_t*)hdr + hdr->tp_mac;
        uint32_t frame_len = hdr->tp_snaplen;
        uint32_t copy_len = frame_len < buf_len ? frame_len : buf_len;
        memcpy(buf, frame, copy_len);

        if (out_ts_seconds != NULL) {
            *out_ts_seconds = hdr->tp_sec;
        }
        if (out_ts_microseconds != NULL) {
            // Метка времени тут - от самого ядра/NIC на момент приёма
            // именно этого кадра (per-packet), точнее, чем прежний
            // ioctl(SIOCGSTAMP), который спрашивал "а когда пришёл
            // последний кадр на сокете вообще" уже после recv().
            *out_ts_microseconds = hdr->tp_nsec / 1000;
        }

        ctx->cur_pkt_idx++;
        if (ctx->cur_pkt_idx >= ctx->cur_num_pkts) {
            // Дочитали блок целиком - отдать его обратно ядру и перейти
            // к следующему по кольцу.
            bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
            ctx->cur_block = (ctx->cur_block + 1) % ctx->block_nr;
            ctx->cur_pkt_idx = 0;
        } else {
            ctx->cur_pkt_offset += hdr->tp_next_offset;
        }

        return (int)copy_len;
    }
}

int raw_socket_attach_filter(raw_socket_ctx_t* ctx, const struct sock_fprog* prog) {
    if (ctx == NULL || prog == NULL) {
        return -1;
    }
    if (setsockopt(ctx->fd, SOL_SOCKET, SO_ATTACH_FILTER, prog, sizeof(*prog)) == -1) {
        perror("setsockopt(SO_ATTACH_FILTER)");
        return -1;
    }
    return 0;
}

void raw_socket_request_stop(raw_socket_ctx_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    atomic_store(&ctx->stop_requested, 1);
}

void  raw_socket_close(raw_socket_ctx_t* ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->promisc_set_by_us) {
        // симметрично включению: снять IFF_PROMISC, который выставили сами,
        // иначе интерфейс останется в promiscuous и после выхода из программы
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ctx->device_name, IFNAMSIZ - 1);

        if (ioctl(ctx->fd, SIOCGIFFLAGS, &ifr) == -1) {
            perror("ioctl(SIOCGIFFLAGS) - failed to read flags while disabling promiscuous mode");
        } else {
            ifr.ifr_flags &= ~IFF_PROMISC;
            if (ioctl(ctx->fd, SIOCSIFFLAGS, &ifr) == -1) {
                perror("ioctl(SIOCSIFFLAGS) - failed to disable promiscuous mode");
            }
        }
    }

    munmap(ctx->ring, ctx->ring_size);
    close(ctx->fd);
    free(ctx);
}


