# my_wireshark

[![CI](https://github.com/MAX959954/my_wireshark/actions/workflows/ci.yml/badge.svg)](https://github.com/MAX959954/my_wireshark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-C11%20%2F%20C%2B%2B17-orange.svg)](#requirements)

A small, from-scratch packet capture and protocol analyzer for Linux, written in C and C++.
It captures live traffic via raw `AF_PACKET` sockets and decodes each frame down through Ethernet,
ARP, IPv4/IPv6, TCP, and UDP, printing a one-line summary per packet — a minimal, educational take
on what tools like Wireshark and tcpdump do under the hood.

```
[#1] 0.123456 len=74 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 IPv4 192.168.1.10 > 93.184.216.34 TCP ...
```

## Features

- **Live capture** via `AF_PACKET` raw sockets in **`PACKET_MMAP`/`TPACKET_V3`** ring-buffer mode
  (`src/c/raw_socket.c`), with an interface picker at startup. The kernel and the process share a
  memory-mapped ring of frames; the kernel fills it without our involvement and we drain it with
  `poll()` instead of one `recv()` per packet — no per-packet syscall, no per-packet copy out of the
  socket buffer. Needs only `CAP_NET_RAW` (root, or `sudo setcap cap_net_raw+ep <binary>`) — no
  separate packet-capture driver/SDK required.
- **`capture_backend_t` interface** (`src/c/capture_backend.h`) — a small vtable of function pointers
  (`list_devices`/`run`/`request_stop`) that `main.cpp` calls through instead of talking to
  `raw_socket.c` directly, so the capture implementation can be swapped (e.g. for tests) without
  touching `main.cpp`.
- **Protocol parsers**, written as small, dependency-free C modules that operate directly on raw byte
  buffers (no copying, no dynamic allocation):
  - Ethernet II (`src/c/eth_parser.c`)
  - ARP (`src/c/arp_parser.c`)
  - IPv4 (`src/c/ip_parser.c`)
  - IPv6 (`src/c/ipv6_parser.c`) — decodes the fixed 40-byte main header; extension headers
    (hop-by-hop, routing, fragment, ...) aren't walked, so dispatch only looks at `next_header`
    directly following it
  - TCP and UDP (`src/c/tcp_udp_parser.c`) — dispatched from both IPv4 (`ip.protocol`) and IPv6
    (`ipv6.next_header`)
- **Checksum verification** for TCP/UDP segments (`src/c/checksum.c`), against either the IPv4
  pseudo-header or the IPv6 one (RFC 2460 §8.1 — 16-byte addresses, a 32-bit upper-layer length,
  and a mandatory UDP checksum with no RFC 768 "sender chose not to compute one" exemption), so
  malformed or corrupted packets are flagged rather than silently mis-decoded.
- **C++ presentation layer** (`src/cpp/`) that formats parsed headers into readable, per-packet summary
  lines (timestamp, capture length, MAC/IP addresses, ports, TTL, flags).
- **Clean shutdown**: `Ctrl+C` is handled via a `SIGINT` handler that pokes `raw_socket_request_stop()`
  (see `capture_backend_request_stop()` in `src/c/capture_backend.h`/`capture_backend_linux.c`), so the
  capture loop exits cleanly instead of being killed mid-packet.
- **pcap file output** (`-w`): captured frames are optionally written to a `.pcap` file using a small
  hand-rolled writer in `capture_backend_linux.c`, openable directly in Wireshark.
- **BPF capture filters** (`-f`, e.g. `-f "tcp and port 443"`): a small from-scratch compiler
  (`src/c/capfilter.c`) turns a `pcap-filter`-like expression into classic BPF bytecode and attaches it
  with `SO_ATTACH_FILTER`, so filtering happens in the kernel, before packets are copied to us at all —
  see [BPF capture filters](#bpf-capture-filters) below.
- **Fuzz-tested parsers** (`src/fuzz/`): every protocol parser has a libFuzzer-compatible harness and a
  seed corpus, replayed under ASan/UBSan on every push and fuzzed for real with libFuzzer in CI — see
  [Fuzzing](#fuzzing) below.

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
    capfilter.c/.h                   # "tcp port 443" -> classic BPF bytecode compiler
  cpp/
    packet.cpp/.h                    # base packet summary (Ethernet/IPv4)
    tcp_packet.cpp/.h                 # TCP-specific summary (IPv4); print_tcp_summary() is shared with IPv6
    udp_packet.cpp/.h                  # UDP-specific summary (IPv4); print_udp_summary() is shared with IPv6
    arp_packet.cpp/.h                  # ARP-specific summary
    ipv6_packet.cpp/.h                 # IPv6 summary, including TCP/UDP-over-IPv6 when parsed
  fuzz/
    fuzz_*.c                          # one libFuzzer harness per parser
    standalone_driver.c                # plain main() fallback when Clang/libFuzzer isn't available
    corpus/<parser>/*.bin               # seed corpora, replayed as regression tests every push
```

## Requirements

- Linux (or WSL)
- CMake ≥ 3.20
- A C11 / C++17 toolchain (GCC or Clang) — Clang is only required for real fuzzing (`-DENABLE_LIBFUZZER=ON`)

## Building

```bash
cmake -B out
cmake --build out
```

## BPF capture filters

`-f "<expression>"` compiles a small subset of `pcap-filter(7)` syntax straight to classic BPF
bytecode and attaches it to the capture socket with `SO_ATTACH_FILTER` — the kernel drops non-matching
frames itself, before they're ever copied into this process:

```
primitive := 'tcp' | 'udp' | 'icmp' | 'ip' | 'ip6' | 'arp'
           | ['src'|'dst'] 'host' A.B.C.D
           | ['src'|'dst'] 'port' NUM
           | ['src'|'dst'] 'net' A.B.C.D '/' PREFIXLEN
expr      := primitive (('and'|'&&'|'or'|'||') primitive)*   # 'not'/'!' and '(' ')' also work
```

e.g. `-f "tcp and (port 80 or port 443)"`, `-f "host 10.0.0.5 and not icmp"`.

The compiler (`src/c/capfilter.c`) is a textbook three-stage pipeline: a hand-written lexer, a
recursive-descent parser building an AST, and a codegen pass that walks the AST once, emitting BPF
instructions with classic *backpatching* for short-circuit `and`/`or`/`not` (each node compiles to code
that either falls through on true or jumps on false; the jump targets get filled in once the
surrounding context — literally the next instruction's address — is known). `port N` reproduces the
same trick real `tcpdump`-generated filters use to reach a variable-offset TCP/UDP header: `BPF_MSH`
loads the IPv4 header's IHL nibble into the X register, then `BPF_IND` indexes off it.

It's deliberately a subset: primitives must be joined with an explicit `and`/`or` (no implicit
juxtaposition like real `tcpdump`'s `"tcp port 80"`), and `host`/`net` only match IPv4 addresses —
the BPF compiler doesn't yet emit the wider loads/compares an IPv6 address needs (that's a filter-
language gap only; the analyzer's own IPv6 parsing is unaffected — see above). `src/tests/test_capfilter.c`
checks the generated bytecode against `src/tests/bpf_interp.c`, a ~100-line reference BPF interpreter
written just for the tests, so the whole thing is verified without needing root or a real socket.

## Fuzzing

Every parser gets a `LLVMFuzzerTestOneInput` harness in `src/fuzz/` (`fuzz_eth.c`, `fuzz_arp.c`,
`fuzz_ip.c`, `fuzz_ipv6.c`, `fuzz_tcp_udp.c`) — they're an obvious fuzzing target because every parser
is a pure function of `(const uint8_t* data, uint32_t length)` with no side effects, no I/O, and (per
`ip_parser.c`'s bounds checks, which this whole exercise was built to double-check) careful-looking
length validation before every read.

Two ways to run them, because a real libFuzzer binary needs Clang:

- **Everywhere (GCC included):** each harness also links against `standalone_driver.c`, a plain
  `main()` that replays files given on argv. CMake wires this up as `fuzz_<name>_replay`, registered as
  an ordinary `ctest` test that replays `src/fuzz/corpus/<name>/*.bin` — so it runs under ASan/UBSan in
  the existing CI matrix on every push, no new dependency. This catches *regressions*, not new bugs.
- **Real fuzzing (Clang only):** `cmake -B out -DCMAKE_C_COMPILER=clang -DENABLE_LIBFUZZER=ON` builds
  `fuzz_<name>` binaries with `-fsanitize=fuzzer,address,undefined`. Run one directly:

  ```bash
  ./out/src/fuzz/fuzz_ip -max_total_time=60 src/fuzz/corpus/ip
  ```

  CI's `fuzz-smoke` job does exactly this for all five targets, 30 seconds each, on every push, and
  uploads any crashing input it finds as a build artifact.

Seed corpora (`src/fuzz/corpus/`) are small hand-built valid/near-valid frames (see
`generate_seed_corpus.c` in that directory) rather than empty — mutating from a header that already
passes the length/version checks reaches far more code than mutating from nothing.

## Usage

Run the built executable as root, or grant the binary `CAP_NET_RAW` directly
(`sudo setcap cap_net_raw+ep out/my_wireshark`):

```bash
./out/my_wireshark
```

You'll be prompted to pick a capture interface from the list of available devices; captured packets
are then decoded and printed to stdout in real time until you stop the capture with `Ctrl+C`.

## License

MIT — see [LICENSE](LICENSE).
