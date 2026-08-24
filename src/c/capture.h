#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>

#ifdef __cplusplus 
extern "C" {
#endif 

#define CAPTURE_MAX_DEVICES 32
#define CAPTURE_NAME_LEN   256

typedef struct {
	char name[CAPTURE_NAME_LEN];
	char description[CAPTURE_NAME_LEN];
} capture_device_t ;

//show the max device interfaces found in that host
//if no return 0 
int capture_list_device(capture_device_t * output , int max_device);


typedef void (*capture_packet_cb) (const uint8_t* packet, uint32_t lengt,
	uint32_t ts_seconds, uint32_t ts_microseconds, void* user_data);

//open device and blocks the calling thread invoking 'cb'
// for every captured packet until an error occurs . Returns 0 on clean stop , -1
int capture_run(const char * device_name , capture_packet_cb cb , void * user_data);

/*
запрашивает остановку активного capture_run(): дёргает pcap_breakloop() на
его handle, из-за чего pcap_loop() выходит и capture_run() возвращает 0.
capture_run() сам вызывает эту функцию из своего обработчика SIGINT
(Ctrl+C), поэтому обычно вызывать её вручную не требуется — она экспортирована
на случай, если понадобится остановить захват из другого места (например,
из потока GUI). Если capture_run() сейчас не выполняется — не делает ничего.
Безопасно вызывать из обработчика сигнала.
*/
void capture_request_stop(void);

#ifdef __cplusplus 
}
#endif 

#endif  /*CAPTURE_H*/

