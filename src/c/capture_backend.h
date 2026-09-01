#ifndef CAPTURE_BACKEND_H
#define CAPTURE_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

 /*
Собрать в одном месте всё, что не относится к чистому захвату:
запись в .pcap-файл, обработку
Ctrl+C, предупреждение про неподдержанный BPF-фильтр

Дать точку подмены для тестов — можно подсунуть фейковый
бэкенд, который «проигрывает» пакеты из
массива вместо реальной карты.
 */

#define CAPTURE_MAX_DEVICES 32
#define CAPTURE_NAME_LEN    256

typedef struct {
    char name[CAPTURE_NAME_LEN]; // "eth0"
    char description[CAPTURE_NAME_LEN]; // человекочитаемое описание (сейчас всегда пустое)
} capture_device_t;

//Это тип указателя на функцию. capture_packet_cb — «функция,
// которую бэкенд зовёт на каждый пойманный пакет»
typedef void (*capture_packet_cb)(const uint8_t* packet, uint32_t length,
    uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data);

//Сам интерфейс — vtable
typedef struct {

    /*
    Три поля — указатели на функции. Структура целиком = «таблица
    методов» бэкенда. Разные бэкенды
    заполняют её разными реализациями. Это то, что в C++ компилятор
    генерирует автоматически для
    виртуальных методов; здесь — руками.
    */
    
    int (*list_devices)(capture_device_t* output, int max_devices);

 
    int (*run)(const char* device_name, const char* bpf_filter,
        const char* pcap_output_path, capture_packet_cb cb, void* user_data);

  
    void (*request_stop)(void);
} capture_backend_t;

// вернуть активный бэкенд
const capture_backend_t* capture_backend_get(void);

// обёртки, чтобы не писать capture_backend_get()->list_devices() каждый раз
int capture_backend_list_devices(capture_device_t* output, int max_devices);
int capture_backend_run(const char* device_name, const char* bpf_filter,
    const char* pcap_output_path, capture_packet_cb cb, void* user_data);
void capture_backend_request_stop(void);

#ifdef __cplusplus
}
#endif

#endif 
