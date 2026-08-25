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

# AF_PACKET-based capture (src/c/raw_socket.c, wrapped behind the
# capture_backend_t interface in src/c/capture_backend.h/.c) needs only
# CAP_NET_RAW, not a separate packet-capture driver/SDK like Npcap.
add_executable(my_wireshark
    src/main.cpp
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
    src/c/capture_backend.h
    src/c/capture_backend_linux.c
    src/c/raw_socket.c
    src/c/raw_socket.h
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

target_include_directories(my_wireshark PRIVATE src)

target_compile_options(my_wireshark PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra>
)
