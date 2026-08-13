cmake_minimum_required(VERSION 3.20)
project(my_wireshark C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT WIN32)
    message(FATAL_ERROR "This project currently targets Windows + Npcap only.")
endif()

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

add_executable(my_wireshark
    src/main.cpp
    src/c/capture.c
    src/c/capture.h
)

set_source_files_properties(src/c/capture.c PROPERTIES LANGUAGE C)

target_include_directories(my_wireshark PRIVATE
    src
    "${NPCAP_SDK_DIR}/Include"
)

target_link_directories(my_wireshark PRIVATE "${NPCAP_LIB_DIR}")
target_link_libraries(my_wireshark PRIVATE wpcap Packet ws2_32)
