#include "raw_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct raw_socket_ctx {
    int fd; // файловый дескриптор сокета
    atomic_int stop_requested;  // флаг остановки, атомарный
}; 

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

    if (!(ifr.ifr_flags & IFF_PROMISC)) {
        ifr.ifr_flags |= IFF_PROMISC; // добавить бит "promiscuous"
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) { // записать обратно 
            perror("ioctl(SIOCSIFFLAGS) - promiscuous mode unavailable");
        }
    }

    //Таймаут на приём

    /*
    recv блокирующий — без таймаута он висел бы вечно, ожидая пакет
    , и не замечал бы флаг
    stop_requested. С SO_RCVTIMEO recv сам возвращается с
    EAGAIN каждые 200 мс → цикл проверяет флаг
    → максимум 200 мс задержки
    */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000; 
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(fd);
        return NULL;
    }

    //Выделить контекст
    raw_socket_ctx_t* ctx = malloc(sizeof(raw_socket_ctx_t));
    if (ctx == NULL) {
        perror("malloc");
        close(fd);
        return NULL;
    }

    ctx->fd = fd;
    atomic_init(&ctx->stop_requested, 0);
    return ctx;
}

int raw_socket_recv(raw_socket_ctx_t* ctx, uint8_t* buf, uint32_t buf_len,
    uint32_t  * out_ts_seconds , uint32_t  * out_ts_microseconds ) {

    if (ctx == NULL || buf == NULL) {
        return -1;
    }

    for (;;) {
        if (atomic_load(&ctx->stop_requested)) {
            return 0; //// 0 = "запрошена остановка", чистое завершение
        }
        ssize_t n = recv(ctx->fd, buf, buf_len, 0);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue; // таймаут 200мс или прерывание сигналом — не ошибка, крутимся дальше
            } 
            perror("recv");
            return -1;
        }

        /*
        SIOCGSTAMP спрашивает у ядра, когда именно этот кадр был принят сетевой картой — точнее, чем
        время «сейчас», т.к. между приёмом и обработкой есть задержка. Если ядро метку не дало —
        берём текущее время как приближение.
        */
        struct timeval tv;
        if (ioctl(ctx->fd, SIOCGSTAMP, &tv) == -1) {
            gettimeofday(&tv, NULL);
        }

        if (out_ts_seconds != NULL) {
            *out_ts_seconds = (uint32_t)tv.tv_sec;
        }

        if (out_ts_microseconds != NULL) {
            *out_ts_microseconds = (uint32_t)tv.tv_usec;
        }

        return (int)n;
    };
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
    close(ctx->fd);
    free(ctx);
}


