# Two tiers, see README's "Fuzzing" section for the full rationale:
#
# 1. Always built, any compiler: "*_replay" binaries link each harness
#    against standalone_driver.c (a plain main(), no libFuzzer needed) and
#    are registered as ordinary ctest tests that replay the seed corpus.
#    This is what runs in the existing CI matrix (gcc, ASan/UBSan) on
#    every push, with zero extra dependencies.
#
# 2. Only with -DENABLE_LIBFUZZER=ON and clang: real libFuzzer binaries
#    ("fuzz_eth" etc, no "_replay" suffix) built with
#    -fsanitize=fuzzer,address,undefined, for actual exploratory fuzzing
#    sessions and for the dedicated CI job that runs each one for a
#    bounded amount of time as a stronger regression gate.

function(add_fuzz_target name)
    add_executable(fuzz_${name}_replay fuzz_${name}.c standalone_driver.c)
    target_link_libraries(fuzz_${name}_replay PRIVATE wireshark_parsers)
    target_compile_options(fuzz_${name}_replay PRIVATE -Wall -Wextra)

    file(GLOB corpus_files "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name}/*.bin")
    add_test(NAME fuzz_${name}_corpus COMMAND fuzz_${name}_replay ${corpus_files})

    if (ENABLE_LIBFUZZER)
        if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
            message(FATAL_ERROR "ENABLE_LIBFUZZER requires Clang (got ${CMAKE_C_COMPILER_ID}); "
                "configure with -DCMAKE_C_COMPILER=clang")
        endif()

        add_executable(fuzz_${name} fuzz_${name}.c)
        target_link_libraries(fuzz_${name} PRIVATE wireshark_parsers)
        target_compile_options(fuzz_${name} PRIVATE
            -Wall -Wextra -g -O1 -fsanitize=fuzzer,address,undefined)
        target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer,address,undefined)

        # Bounded smoke run wired into ctest too, not just left as a
        # manual exploratory tool - a fresh regression each push, not
        # just at release time.
        add_test(NAME fuzz_${name}_smoke
            COMMAND fuzz_${name} -max_total_time=10 -close_fd_mask=3
                "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name}")
    endif()
endfunction()

add_fuzz_target(eth)
add_fuzz_target(arp)
add_fuzz_target(ip)
add_fuzz_target(ipv6)
add_fuzz_target(tcp_udp)
add_fuzz_target(icmp)
