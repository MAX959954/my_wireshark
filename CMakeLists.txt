cmake_minimum_required(VERSION 3.20)
project(my_wireshark C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT UNIX)
    message(FATAL_ERROR
        "my_wireshark targets Linux only: capture is done via AF_PACKET raw "
        "sockets (src/c/raw_socket.c), which needs Linux-specific headers "
        "(linux/if_packet.h etc). Windows/Npcap support has been removed.")
endif()

# Protocol parsers as a separate static library: pure, dependency-free C that
# both my_wireshark and the unit tests under src/tests/ link against, so the
# parser sources aren't compiled twice and tests exercise the exact same
# object code as the real binary.
add_library(wireshark_parsers STATIC
    src/c/checksum.c
    src/c/checksum.h
    src/c/eth_parser.c
    src/c/eth_parser.h
    src/c/ip_parser.c
    src/c/ip_parser.h
    src/c/ipv6_parser.c
    src/c/ipv6_parser.h
    src/c/arp_parser.c
    src/c/arp_parser.h
    src/c/tcp_udp_parser.c
    src/c/tcp_udp_parser.h)

target_include_directories(wireshark_parsers PUBLIC src)

target_compile_options(wireshark_parsers PRIVATE -Wall -Wextra)

# C++ presentation layer: turns parsed headers into human-readable summary
# lines. Built as a library (same reasoning as wireshark_parsers above) so
# main.cpp and test_capture_pipeline.cpp link the exact same object code -
# the print half of the "capture -> parse -> print" pipeline is exercised
# identically whether the packets come from a real NIC or a fake backend.
add_library(wireshark_presentation STATIC
    src/cpp/packet.cpp
    src/cpp/packet.h
    src/cpp/tcp_packet.cpp
    src/cpp/tcp_packet.h
    src/cpp/udp_packet.cpp
    src/cpp/udp_packet.h
    src/cpp/arp_packet.cpp
    src/cpp/arp_packet.h
    src/cpp/ipv6_packet.cpp
    src/cpp/ipv6_packet.h
    src/cpp/packet_printer.cpp
    src/cpp/packet_printer.h)

target_include_directories(wireshark_presentation PUBLIC src)
target_link_libraries(wireshark_presentation PUBLIC wireshark_parsers)
target_compile_options(wireshark_presentation PRIVATE -Wall -Wextra)

# AF_PACKET-based capture (src/c/raw_socket.c, wrapped behind the
# capture_backend_t interface in src/c/capture_backend.h/.c) needs only
# CAP_NET_RAW, not a separate packet-capture driver/SDK like Npcap.
add_executable(my_wireshark
    src/main.cpp
    src/c/capture_backend.h
    src/c/capture_backend_linux.c
    src/c/raw_socket.c
    src/c/raw_socket.h)

target_include_directories(my_wireshark PRIVATE src)
target_link_libraries(my_wireshark PRIVATE wireshark_presentation)

target_compile_options(my_wireshark PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra>
)

enable_testing()
add_subdirectory(src/tests)
