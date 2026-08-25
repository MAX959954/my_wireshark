#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdio.h>

static int test_failures = 0;

#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            test_failures++; \
        } \
    } while (0)

#define TEST_RUN(fn) \
    do { \
        fprintf(stderr, "-- %s\n", #fn); \
        fn(); \
    } while (0)

#define TEST_MAIN_END() return test_failures == 0 ? 0 : 1

#endif /* TEST_UTIL_H */
