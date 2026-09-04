# netforge

Packet crafting and parsing in modern C++17 — no dependencies, no framework. Zero-copy buffer cursors, wire-accurate protocol structs, network-byte-order handling, and safe bounds-checked access built in.

Think *Scapy*, but a C++17 library you can drop into `strace`-free bare-metal and userspace tooling alike. Craft packets byte-for-byte by hand, parse them off the wire without alignment traps, and never trust input blindly.

## Features

- **Zero-dependency core** — headers + a handful of `.cpp` files, C++17 only.
- **Safe, zero-copy `buffer` cursor** — bounds-checked reads/writes, unaligned-safe access, throwing and non-throwing paths, byte slices for payloads.
- **Wire-order primitives** — `produce`/`consume` handle network byte order for you; only `ntoh`-style helpers, so no hidden framework magic.
- **Protocol layers**
  - Ethernet
  - IPv4 (header + checksum)
  - IPv6 *(WIP)*
  - TCP (flags, header length, pseudo-header checksum)
  - UDP
  - ICMP *(WIP)*
  - DNS (names, questions, answers, pointer compression decode)
  - HTTP (request/response serialize + parse)
- **Honest errors** — malformed or truncated packets raise `std::out_of_range` instead of overrunning buffers.

## Current status

The layer core is implemented and smoke-tested (round-trip: craft DNS → UDP → IPv4 → bytes → parse back). IO backends (pcap, raw sockets, sniffing), Python bindings via pybind11, and extra layers are planned but not yet built — see [Roadmap](#roadmap).

## Quick start

```bash
# no build system wired up yet — the library is small enough to compile directly
g++ -std=c++17 -I include your_file.cpp src/layers/ethernet.cpp \
    src/layers/ipv4.cpp src/layers/udp.cpp src/layers/tcp.cpp \
    src/layers/dns.cpp src/layers/http.cpp -o your_binary
```

### Craft a DNS query

```cpp
#include <cstdio>
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/layers/dns.hpp"

int main() {
    std::vector<uint8_t> wire(512);
    netforge::buffer buf(wire.data(), wire.size());

    netforge::dns_message_t msg;
    msg.header.id = 0x1234;
    msg.header.rd = 1;

    netforge::dns_message_t::question_t q;
    q.qname = "google.com";
    q.qtype = 1;
    q.qclass = 1;
    msg.questions.push_back(q);

    msg.produce(buf);
    std::printf("crafted %zu-byte DNS query\n", buf.position());
    return 0;
}
```

### Parse a packet back

```cpp
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/udp.hpp"
#include "netforge/layers/dns.hpp"

void handle_packet(uint8_t* bytes, std::size_t len) {
    netforge::buffer buf(bytes, len);

    netforge::ethernet_header_t eth = netforge::ethernet_header_t::consume(buf);
    netforge::ipv4_header_t ip = netforge::ipv4_header_t::consume(buf);
    netforge::udp_header_t udp = netforge::udp_header_t::consume(buf);

    if (ip.protocol == 17 && udp.dst_port == 53) {
        netforge::dns_message_t msg = netforge::dns_message_t::consume(buf);
        for (const auto& q : msg.questions)
            std::printf("question: %s\n", q.qname.c_str());
    }
}
```

## Layout

```
include/netforge/
  buffer/   buffer cursor + byte-order utilities
  layers/   protocol header structs (produce/consume/checksum)
  io/       pcap, raw socket, sniffer backends      (WIP)
  packet/   composite packet builder                (WIP)
  parser/   checksum + dissector helpers            (WIP)
src/        layer implementations
bindings/   pybind11 module                         (WIP)
python/     python package stubs                    (WIP)
examples/   cpp + python craft/sniff/dns examples
tests/      unit test scaffolding (cpp + python)
benchmarks/ parse benchmarks                        (WIP)
```

## Roadmap

- CMake build (static lib + tests + examples + pybind targets)
- `ipv6` and `icmp` layers
- `io/`: raw-socket send, pcap live capture + offline read, sniffer
- `parser/`: dissect helpers and capture-file parsing
- pybind11 Python bindings (`import netforge`)
- Real unit tests (the `tests/cpp/*` scaffold files are in place)

## License

MIT — see [LICENSE](LICENSE).