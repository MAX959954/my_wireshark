cmake_minimum_required(VERSION 3.20)
project(my_wireshark C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32)

# Npcap SDK (headers + import libs) is separate from the Npcap runtime driver.
# 1. Install the Npcap runtime: https://npcap.com/#download -> "Npcap installer"
#    (check "Install Npcap in WinPcap API-compatible Mode").
# 2. Download the SDK zip from the same page -> "Npcap SDK", unzip it anywhere.
# 3. Configure with -DNPCAP_SDK_DIR=<path-to-unzipped-sdk>, or set the
#    NPCAP_SDK_DIR environment variable before running cmake.
set(NPCAP_SDK_DIR "" CACHE PATH "Path to the unzipped Npcap SDK")

if (NOT NPCAP_SDK_DIR AND DEFINED ENV{NPCAP_SDK_DIR})
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
endif()

if (NOT EXISTS "${NPCAP_SDK_DIR}/Include/pcap.h")
    message(FATAL_ERROR
        "Npcap SDK not found (looked for Include/pcap.h under NPCAP_SDK_DIR="
        "'${NPCAP_SDK_DIR}'). Download the SDK from https://npcap.com/#download, "
        "unzip it, then reconfigure with -DNPCAP_SDK_DIR=<path-to-unzipped-sdk>.")
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
else()
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib")
endif()

# raw_socket.c/.h implement an AF_PACKET-based capture path for Linux/WSL and
# are not part of this Windows+Npcap target (they won't compile with MSVC's
# Windows headers); see the UNIX branch below for their build target.
add_executable(my_wireshark
    src/main.cpp
    src/c/capture.c
    src/c/capture.h
    src/c/eth_parser.c
    src/c/eth_parser.h
    src/c/ip_parser.c
    src/c/ip_parser.h
    src/c/tcp_udp_parser.c
    src/c/tcp_udp_parser.h)

set_source_files_properties(
    src/c/capture.c
    src/c/eth_parser.c
    src/c/ip_parser.c
    src/c/tcp_udp_parser.c
    PROPERTIES LANGUAGE C
)

target_include_directories(my_wireshark PRIVATE
    src
    "${NPCAP_SDK_DIR}/Include"
)

target_link_directories(my_wireshark PRIVATE "${NPCAP_LIB_DIR}")
target_link_libraries(my_wireshark PRIVATE wpcap Packet ws2_32)

target_compile_options(my_wireshark PRIVATE
    $<$<C_COMPILER_ID:MSVC>:/W4>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<AND:$<COMPILE_LANGUAGE:C>,$<NOT:$<C_COMPILER_ID:MSVC>>>:-Wall -Wextra>
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:-Wall -Wextra>
)

elseif (UNIX)

# AF_PACKET-based capture path for Linux/WSL, built separately from the
# Windows+Npcap target above so it gets a real compile command (and thus
# working IntelliSense) under the Linux-GCC-Debug configuration.
add_executable(raw_socket_test
    src/c/raw_socket.c
    src/c/raw_socket.h)

target_include_directories(raw_socket_test PRIVATE src)

target_compile_options(raw_socket_test PRIVATE -Wall -Wextra)

endif()
