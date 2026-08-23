<div align="center">

# 🦈 my_wireshark

**A from-scratch packet capture and protocol analyzer, written in C and C++.**

Captures live traffic via [Npcap](https://npcap.com/) and decodes it — frame by frame — down
through Ethernet, IPv4/IPv6, ARP, TCP, and UDP, printing a clean, one-line summary per packet.
A minimal, educational look at what tools like Wireshark and tcpdump do under the hood.

![Language](https://img.shields.io/badge/language-C11%20%2F%20C%2B%2B17-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%2FWSL-lightgrey)
![Build](https://img.shields.io/badge/build-CMake-064F8C)

</div>

---

## 📦 Example output

```
[#1] 0.123456 len=74 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 [TCP] 192.168.1.10 > 93.184.216.34 ttl=64
[#2] 0.123789 len=98 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 [UDP] 192.168.1.10 > 8.8.8.8 ttl=64
```

## ✨ Features

- **Live capture** on Windows via Npcap (WinPcap-compatible API), with an interface picker at startup.
- **Protocol parsers** written as small, dependency-free C modules operating directly on raw
  byte buffers — no copying, no dynamic allocation:

  | Protocol | Source |
  |---|---|
  | Ethernet II | `src/c/eth_parser.c` |
  | ARP | `src/c/arp_parser.c` |
  | IPv4 | `src/c/ip_parser.c` |
  | IPv6 | `src/c/ipv6_parser.c` |
  | TCP / UDP | `src/c/tcp_udp_parser.c` |

- **C++ presentation layer** (`src/cpp/`) that turns parsed headers into readable per-packet
  summaries — timestamp, capture length, MAC/IP addresses, ports, TTL, flags.
- **Alternate Linux/WSL capture path** (`src/c/raw_socket.c`) built on `AF_PACKET` raw sockets,
  for developing and testing the C parsers without Npcap.

## 🗂️ Project layout

```
src/
  main.cpp                 entry point — interface selection + capture loop
  c/
    capture.c / .h          Npcap device enumeration + capture loop (Windows)
    raw_socket.c / .h       AF_PACKET capture loop (Linux/WSL)
    eth_parser.c / .h       Ethernet II frame parsing
    arp_parser.c / .h       ARP packet parsing
    ip_parser.c / .h        IPv4 header parsing
    ipv6_parser.c / .h      IPv6 header parsing
    tcp_udp_parser.c / .h   TCP and UDP header parsing
  cpp/
    packet.cpp / .h         base packet summary (Ethernet/IPv4)
    tcp_packet.cpp / .h     TCP-specific summary
    udp_packet.cpp / .h     UDP-specific summary
```

## 🛠️ Requirements

- CMake ≥ 3.20
- A C11 / C++17 toolchain (MSVC or MinGW-w64 on Windows)
- [Npcap runtime](https://npcap.com/#download) — installed **with "WinPcap API-compatible mode"** enabled
- [Npcap SDK](https://npcap.com/#download) (headers + import libraries) — unzipped anywhere on disk

## 🚀 Building

### Windows

```powershell
cmake -B build -DNPCAP_SDK_DIR="C:\path\to\npcap-sdk"
cmake --build build
```

`NPCAP_SDK_DIR` can also be set as an environment variable instead of a CMake argument.

### Linux / WSL (parser-only path)

The Npcap-based target is Windows-only. On Linux/WSL, the `raw_socket_test` target builds the
`AF_PACKET` capture loop instead, letting you exercise the C parsers independently:

```bash
cmake -B build
cmake --build build
sudo ./build/raw_socket_test
```

## ▶️ Running

Live packet capture opens a raw device handle, which requires elevated privileges:

```powershell
# from an Administrator terminal
.\build\Debug\my_wireshark.exe
```

The program lists available capture interfaces, prompts for an index, then prints one summary
line per captured packet until interrupted (Ctrl+C).

## 🧭 Status

| Layer | Parsed | Wired into live capture |
|---|---|---|
| Ethernet | ✅ | ✅ |
| IPv4 | ✅ | ✅ |
| TCP | ✅ | ✅ |
| UDP | ✅ | ✅ |
| ARP | ✅ | ⬜ implemented, not yet dispatched |
| IPv6 | ✅ | ⬜ implemented, not yet dispatched |

Non-IPv4 frames currently print only their Ethernet-layer summary.

## 📄 License

No license file is currently included. Add one (e.g. [MIT](https://choosealicense.com/licenses/mit/))
if you intend to share or accept contributions on this repo.
