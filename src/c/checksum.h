#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

/*
The Internet checksum (RFC 1071) - the algorithm used to verify the
integrity of the IPv4 header, a TCP segment, and a UDP datagram. It only
catches accidental bit corruption (line noise, a bad router NIC), not
deliberate tampering. IPv4, TCP, and UDP all use the same algorithm, so
it's implemented once here and shared.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*
accumulates a running sum over 'data'; 'sum' is the previous partial sum
so calls can be chained (e.g. pseudo-header then segment). Does not fold
the carry - that happens once, at the end, in checksum_verify(). An odd
trailing byte is padded with a zero low byte.
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
