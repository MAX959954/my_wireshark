#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
adds 'data' (network-order, 'len' bytes long) into the not-yet-folded ones'
complement sum 'sum' (RFC 1071). A trailing odd byte is padded with a zero
on the right. Returns the updated, still-unfolded sum, so several chunks
(e.g. a pseudo-header and the segment itself) can be accumulated in turn
before one final fold.
*/
uint32_t checksum_partial(const uint8_t* data, uint32_t len, uint32_t sum);

/*
verifies the checksum already present inside 'data' ('len' bytes long) - the
checksum field does not need to be zeroed first. Returns 1 if the checksum
is correct, 0 otherwise.
*/
int checksum_verify(const uint8_t* data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
