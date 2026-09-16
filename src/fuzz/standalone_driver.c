/*
Minimal libFuzzer-compatible replay driver.

A real libFuzzer binary (built with clang -fsanitize=fuzzer) provides its
own main() that mutates inputs and calls LLVMFuzzerTestOneInput() millions
of times. That binary doesn't exist unless clang is available (see
src/fuzz/CMakeLists.txt / README's Fuzzing section for how to build one).

This file is the fallback main() used everywhere else (plain gcc, CI's
warnings/ASan-UBSan matrix, a contributor without clang installed): it
just replays every file given on argv against LLVMFuzzerTestOneInput() and
lets the sanitizers built into the *parser* library do the actual
checking. It's not fuzzing - it's regression testing against the seed
corpus (and, over time, any crashing input a real fuzzing run found and
that got minimized into the corpus) - but it needs nothing beyond the
same GCC + ASan/UBSan setup the rest of this project's tests already use,
so it runs in ordinary `ctest` on every push.
*/
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <seed-file> [seed-file...]\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        FILE* f = fopen(argv[i], "rb");
        if (f == NULL) {
            perror(argv[i]);
            return 1;
        }
        if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return 1; }
        long len = ftell(f);
        if (len < 0 || fseek(f, 0, SEEK_SET) != 0) { perror("ftell/fseek"); fclose(f); return 1; }

        /* malloc(1) for the zero-length case: passing size 0 to
           LLVMFuzzerTestOneInput is legal and worth covering (empty
           capture buffer), but a NULL data pointer is not something a
           real libFuzzer run would ever pass. */
        uint8_t* buf = malloc(len > 0 ? (size_t)len : 1);
        if (buf == NULL) { fprintf(stderr, "out of memory\n"); fclose(f); return 1; }

        size_t n = fread(buf, 1, (size_t)len, f);
        fclose(f);
        if (n != (size_t)len) {
            fprintf(stderr, "%s: short read\n", argv[i]);
            free(buf);
            return 1;
        }

        LLVMFuzzerTestOneInput(buf, n);
        free(buf);
    }

    fprintf(stderr, "replayed %d input(s) OK\n", argc - 1);
    return 0;
}
