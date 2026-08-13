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

#ifdef __cplusplus 
}
#endif 

#endif  /*CAPTURE_H*/

