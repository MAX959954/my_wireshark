# my_wireshark

A small, from-scratch packet capture and protocol analyzer for Windows, written in C and C++.
It captures live traffic via [Npcap](https://npcap.com/) and decodes each frame down through
Ethernet, IPv4/IPv6, ARP, TCP, and UDP, printing a one-line summary per packet — a minimal,
educational take on what tools like Wireshark and tcpdump do under the hood.

```
0.123456 len=74 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 [TCP] 192.168.1.10 > 93.184.216.34 ttl=64
```

## Features

- **Live capture** on Windows via Npcap (WinPcap-compatible API), with an interface picker at startup.
- **Protocol parsers**, written as small, dependency-free C modules that operate directly on raw
  byte buffers (no copying, no dynamic allocation):
  - Ethernet II (`src/c/eth_parser.c`)
  - ARP (`src/c/arp_parser.c`)
  - IPv4 (`src/c/ip_parser.c`)
  - IPv6 (`src/c/ipv6_parser.c`)
  - TCP (`src/c/tcp_udp_parser.c`)
  - UDP (`src/c/tcp_udp_parser.c`)
- **C++ presentation layer** (`src/cpp/`) that formats parsed headers into readable, per-packet
  summary lines (timestamp, capture length, MAC/IP addresses, ports, TTL, flags).
- **Alternate Linux/WSL capture path** (`src/c/raw_socket.c`) built on `AF_PACKET` raw sockets,
  useful for development and testing the C parsers without Npcap.

## Project layout

```
src/
  main.cpp              # entry point: interface selection + capture loop
  c/
    capture.c/.h         # Npcap device enumeration + capture loop (Windows)
    raw_socket.c/.h       # AF_PACKET capture loop (Linux/WSL)
    eth_parser.c/.h        # Ethernet II frame parsing
    arp_parser.c/.h        # ARP packet parsing
    ip_parser.c/.h          # IPv4 header parsing
    ipv6_parser.c/.h        # IPv6 header parsing
    tcp_udp_parser.c/.h     # TCP and UDP header parsing
  cpp/
    packet.cpp/.h           # base packet summary (Ethernet/IPv4)
    tcp_packet.cpp/.h       # TCP-specific summary
    udp_packet.cpp/.h       # UDP-specific summary
```

## Requirements

- CMake ≥ 3.20
- A C11/C++17 toolchain (MSVC or MinGW-w64 on Windows)
- [Npcap](https://npcap.com/#download) runtime, installed **with "WinPcap API-compatible mode"** enabled
- [Npcap SDK](https://npcap.com/#download) (headers + import libraries), unzipped anywhere on disk

## Building (Windows)

```powershell
cmake -B build -DNPCAP_SDK_DIR="C:\path\to\npcap-sdk"
cmake --build build
```

`NPCAP_SDK_DIR` can also be set as an environment variable instead of a CMake argument.

## Running

Live packet capture opens a raw device handle, which requires elevated privileges:

```powershell
# from an Administrator terminal
.\build\Debug\my_wireshark.exe
```

The program lists available capture interfaces, prompts for an index, then prints one summary
line per captured packet until interrupted (Ctrl+C).

## Building on Linux/WSL (parser-only path)

The Npcap-based target is Windows-only. On Linux/WSL, `raw_socket_test` builds the `AF_PACKET`
capture loop instead, useful for exercising the C parsers independently:

```bash
cmake -B build
cmake --build build
sudo ./build/raw_socket_test
```

## Status

Ethernet, IPv4, TCP, and UDP are parsed and wired into the live packet summary in `main.cpp`.
ARP and IPv6 parsing are implemented and unit-verified but not yet dispatched from the main
capture loop — non-IPv4 frames currently print only their Ethernet-layer summary.
