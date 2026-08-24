# my_wireshark

A small, from-scratch packet capture and protocol analyzer for Windows and Linux, written in C and C++.
It captures live traffic via [Npcap](https://npcap.com/) (or raw `AF_PACKET` sockets on Linux/WSL) and
decodes each frame down through Ethernet, ARP, IPv4/IPv6, TCP, and UDP, printing a one-line summary
per packet — a minimal, educational take on what tools like Wireshark and tcpdump do under the hood.

```
[#1] 0.123456 len=74 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 IPv4 192.168.1.10 > 93.184.216.34 TCP ...
```

## Features

- **Live capture** on Windows via Npcap (WinPcap-compatible API), with an interface picker at startup.
- **Alternate Linux/WSL capture path** (`src/c/raw_socket.c`) built on `AF_PACKET` raw sockets, useful
  for development and testing the C parsers without Npcap.
- **Protocol parsers**, written as small, dependency-free C modules that operate directly on raw byte
  buffers (no copying, no dynamic allocation):
  - Ethernet II (`src/c/eth_parser.c`)
  - ARP (`src/c/arp_parser.c`)
  - IPv4 (`src/c/ip_parser.c`)
  - IPv6 (`src/c/ipv6_parser.c`)
  - TCP and UDP (`src/c/tcp_udp_parser.c`)
- **Checksum verification** for TCP/UDP segments (`src/c/checksum.c`), so malformed or corrupted
  packets are flagged rather than silently mis-decoded.
- **C++ presentation layer** (`src/cpp/`) that formats parsed headers into readable, per-packet summary
  lines (timestamp, capture length, MAC/IP addresses, ports, TTL, flags).
- **Clean shutdown**: `Ctrl+C` is handled via `pcap_breakloop()` (`capture_request_stop()` in
  `src/c/capture.c`/`.h`), so the capture loop exits cleanly instead of being killed mid-packet.

## Project layout

```
src/
  main.cpp                 # entry point: interface selection + capture loop
  c/
    capture.c/.h            # Npcap device enumeration + capture loop (Windows)
    raw_socket.c/.h          # AF_PACKET capture loop (Linux/WSL)
    checksum.c/.h             # TCP/UDP checksum verification
    eth_parser.c/.h            # Ethernet II frame parsing
    arp_parser.c/.h             # ARP packet parsing
    ip_parser.c/.h                # IPv4 header parsing
    ipv6_parser.c/.h               # IPv6 header parsing
    tcp_udp_parser.c/.h             # TCP and UDP header parsing
  cpp/
    packet.cpp/.h                    # base packet summary (Ethernet/IPv4)
    tcp_packet.cpp/.h                 # TCP-specific summary
    udp_packet.cpp/.h                  # UDP-specific summary
```

## Requirements

- CMake ≥ 3.20
- A C11 / C++17 toolchain (MSVC or MinGW-w64 on Windows, GCC/Clang on Linux)
- **Windows only:** [Npcap](https://npcap.com/#download) runtime, installed in
  "WinPcap API-compatible Mode", plus the Npcap SDK for headers/import libraries.

## Building

### Windows (Npcap)

1. Install the Npcap runtime (check **"Install Npcap in WinPcap API-compatible Mode"** during setup).
2. Download the Npcap SDK from the same page and unzip it anywhere.
3. Configure and build, pointing CMake at the unzipped SDK:

   ```bash
   cmake -B out -DNPCAP_SDK_DIR="C:/path/to/npcap-sdk"
   cmake --build out
   ```

   `NPCAP_SDK_DIR` can also be set as an environment variable instead of a CMake flag.

### Linux / WSL (raw sockets)

Builds a separate `raw_socket_test` target using `AF_PACKET`, no Npcap required:

```bash
cmake -B out
cmake --build out
```

## Usage

Run the built executable with administrator/root privileges (raw packet capture requires elevated
access on both Windows and Linux):

```bash
./my_wireshark
```

You'll be prompted to pick a capture interface from the list of available devices; captured packets
are then decoded and printed to stdout in real time until you stop the capture with `Ctrl+C`.

## License

No license has been chosen yet — add one (e.g. MIT) before treating this as open source others can
freely reuse.
