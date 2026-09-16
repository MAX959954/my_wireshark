function(add_parser_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE wireshark_parsers)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_parser_test(test_eth_parser)
add_parser_test(test_arp_parser)
add_parser_test(test_ip_parser)
add_parser_test(test_ipv6_parser)
add_parser_test(test_tcp_udp_parser)
add_parser_test(test_checksum)

# End-to-end test: swaps capture_backend_t's real Linux/AF_PACKET
# implementation for fake_capture_backend.c (see its header comment) and
# drives the full capture -> parse -> print pipeline through it.
add_executable(test_capture_pipeline
    test_capture_pipeline.cpp
    fake_capture_backend.c
    fake_capture_backend.h)
target_link_libraries(test_capture_pipeline PRIVATE wireshark_presentation)
target_compile_options(test_capture_pipeline PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra>
)
add_test(NAME test_capture_pipeline COMMAND test_capture_pipeline)
