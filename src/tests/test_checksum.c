#include "test_util.h"
#include "c/checksum.h"

static void partial_sums_pairs_of_bytes_big_endian(void) {
    uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
    uint32_t sum = checksum_partial(data, sizeof(data), 0);
    TEST_ASSERT(sum == 0x68ACu); /* 0x1234 + 0x5678 */
}

static void partial_pads_trailing_odd_byte_on_the_right(void) {
    uint8_t data[] = {0xAB};
    uint32_t sum = checksum_partial(data, sizeof(data), 0);
    TEST_ASSERT(sum == 0xAB00u); /* treated as the high byte of a 16-bit word */
}

static void partial_accumulates_into_an_existing_sum(void) {
    uint8_t data[] = {0x00, 0x01};
    uint32_t sum = checksum_partial(data, sizeof(data), 0x1000);
    TEST_ASSERT(sum == 0x1001u);
}

static void verify_accepts_a_correct_checksum(void) {
    /* payload 0x1234,0x5678 with checksum field 0x9753 appended - together
       they fold to the all-ones 0xFFFF that a valid Internet checksum leaves */
    uint8_t data[] = {0x12, 0x34, 0x56, 0x78, 0x97, 0x53};
    TEST_ASSERT(checksum_verify(data, sizeof(data)) == 1);
}

static void verify_rejects_corrupted_data(void) {
    uint8_t data[] = {0x13, 0x34, 0x56, 0x78, 0x97, 0x53}; /* first byte flipped */
    TEST_ASSERT(checksum_verify(data, sizeof(data)) == 0);
}

int main(void) {
    TEST_RUN(partial_sums_pairs_of_bytes_big_endian);
    TEST_RUN(partial_pads_trailing_odd_byte_on_the_right);
    TEST_RUN(partial_accumulates_into_an_existing_sum);
    TEST_RUN(verify_accepts_a_correct_checksum);
    TEST_RUN(verify_rejects_corrupted_data);
    TEST_MAIN_END();
}
