# my_wireshark

A small, from-scratch packet capture and protocol analyzer for Linux, written in C and C++.
It captures live traffic via raw `AF_PACKET` sockets and decodes each frame down through Ethernet,
ARP, IPv4/IPv6, TCP, and UDP, printing a one-line summary per packet — a minimal, educational take
on what tools like Wireshark and tcpdump do under the hood.

```
[#1] 0.123456 len=74 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 IPv4 192.168.1.10 > 93.184.216.34 TCP ...
```

## Features

- **Live capture** via `AF_PACKET` raw sockets (`src/c/raw_socket.c`), with an interface picker at
  startup. Needs only `CAP_NET_RAW` (root, or `sudo setcap cap_net_raw+ep <binary>`) — no separate
  packet-capture driver/SDK required.
- **`capture_backend_t` interface** (`src/c/capture_backend.h`) — a small vtable of function pointers
  (`list_devices`/`run`/`request_stop`) that `main.cpp` calls through instead of talking to
  `raw_socket.c` directly, so the capture implementation can be swapped (e.g. for tests) without
  touching `main.cpp`.
- **Protocol parsers**, written as small, dependency-free C modules that operate directly on raw byte
  buffers (no copying, no dynamic allocation):
  - Ethernet II (`src/c/eth_parser.c`)
  - ARP (`src/c/arp_parser.c`)
  - IPv4 (`src/c/ip_parser.c`)
  - IPv6 (`src/c/ipv6_parser.c`) — header only; TCP/UDP-over-IPv6 payloads aren't
    decoded further (no IPv6 pseudo-header checksum support yet)
  - TCP and UDP (`src/c/tcp_udp_parser.c`) — dispatched from IPv4 only
- **Checksum verification** for TCP/UDP segments (`src/c/checksum.c`), so malformed or corrupted
  packets are flagged rather than silently mis-decoded.
- **C++ presentation layer** (`src/cpp/`) that formats parsed headers into readable, per-packet summary
  lines (timestamp, capture length, MAC/IP addresses, ports, TTL, flags).
- **Clean shutdown**: `Ctrl+C` is handled via a `SIGINT` handler that pokes `raw_socket_request_stop()`
  (see `capture_backend_request_stop()` in `src/c/capture_backend.h`/`capture_backend_linux.c`), so the
  capture loop exits cleanly instead of being killed mid-packet.
- **pcap file output** (`-w`): captured frames are optionally written to a `.pcap` file using a small
  hand-rolled writer in `capture_backend_linux.c`, openable directly in Wireshark. BPF filtering (`-f`)
  is not currently supported by the raw-socket backend and is a no-op with a warning.

## Project layout

```
src/
  main.cpp                 # entry point: interface selection + capture loop
  c/
    capture_backend.h/.c     # capture_backend_t interface (function-pointer vtable)
    capture_backend_linux.c  # Linux implementation: wraps raw_socket.c + writes .pcap output
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
    arp_packet.cpp/.h                  # ARP-specific summary
    ipv6_packet.cpp/.h                 # IPv6-specific summary (header only)
```

## Requirements

- Linux (or WSL)
- CMake ≥ 3.20
- A C11 / C++17 toolchain (GCC or Clang)

## Building

```bash
cmake -B out
cmake --build out
```

## Usage

Run the built executable as root, or grant the binary `CAP_NET_RAW` directly
(`sudo setcap cap_net_raw+ep out/my_wireshark`):

```bash
./out/my_wireshark
```

You'll be prompted to pick a capture interface from the list of available devices; captured packets
are then decoded and printed to stdout in real time until you stop the capture with `Ctrl+C`.

## License

No license has been chosen yet — add one (e.g. MIT) before treating this as open source others can
freely reuse.
