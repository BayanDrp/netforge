# netforge

Packet crafting and parsing in C++17. Zero-copy buffer cursors, wire-accurate protocol
structs, network-byte-order handling, bounds-checked access — and Python bindings you can
`import netforge`.

Think *Scapy*, but as a C++17 library: ~5 Mpps layer parsing and ~3 Mpps frame building,
measured on a 42-byte frame (see [Benchmarks](#benchmarks)).

## Features

- **Header-driven layers** — host-order field structs; `produce()`/`consume()` translate
  to/from the wire with explicit byte-order conversion.
- **Safe, zero-copy `buffer` cursor** — bounds-checked reads; over-reading throws
  `std::out_of_range`, never overruns.
- **Composition** — chain layers into one frame:
  `pkt.add(eth); pkt.add(ip); pkt.add(udp); pkt.add(dns);`
- **Protocol layers**
  - Ethernet
  - IPv4 (helper fields, header checksum)
  - IPv6 (fixed 40-byte header, no checksum)
  - TCP (flags, header length, pseudo-header checksum)
  - UDP (pseudo-header checksum)
  - ICMP
  - DNS (names, questions, answers, compression-pointer decode)
  - HTTP (serialize + parse)
- **Parser** — `parser::dissect_frame()` walks a capture once: eth → ipv4/ipv6 →
  udp/tcp/icmp, with per-protocol checksum-validity flags and a payload pointer.
- **IO** — raw `AF_PACKET` sender (root required) and libpcap sniffer +
  `list_interfaces()`.
- **Python bindings** (pybind11) — same layers, `Packet`, `RawSocket`, `Sniffer` from
  Python, plus `make_dns_query()`.

## Building

Requires: CMake ≥ 3.14, a C++17 compiler. Optional: libpcap (sniffer), pybind11 +
Python dev (bindings).

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build                 # lib + examples + tests + bindings
ctest --test-dir build              # 5 unit tests
```

Python bindings (installs an editable package; `--break-system-packages` needed on
PEP 668-managed distros):

```bash
pip install -e . --break-system-packages
python -c "import netforge; print(netforge.list_interfaces())"
```

## Quick start (C++)

### Craft a DNS query frame

```cpp
#include <cstdio>
#include <vector>

#include "netforge/layers/dns.hpp"
#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/udp.hpp"
#include "netforge/packet/packet.hpp"

int main() {
    netforge::dns_message_t msg;
    msg.header.id = 0x1234;
    msg.header.rd = 1;
    netforge::dns_message_t::question_t q;
    q.qname = "google.com";
    q.qtype = 1;
    q.qclass = 1;
    msg.questions.push_back(q);

    netforge::packet pkt;
    netforge::ethernet_header_t eth{};
    eth.ethertype = 0x0800;
    netforge::ipv4_header_t ip{};
    ip.protocol = 17;
    ip.source_ip = 0x7F000001;   // 127.0.0.1
    ip.destination_ip = 0x7F000001;
    pkt.add(eth);
    pkt.add(ip);

    netforge::udp_header_t udp{};
    udp.src_port = 53000;
    udp.dst_port = 53;
    pkt.add(udp);
    pkt.add(msg);

    std::printf("crafted %zu-byte frame\n", pkt.size());
}
```

### Parse a packet back

```cpp
#include "netforge/buffer/buffer.hpp"
#include "netforge/layers/dns.hpp"
#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/udp.hpp"

void handle_packet(uint8_t* bytes, std::size_t len) {
    netforge::buffer buf(bytes, len);
    netforge::ethernet_header_t eth = netforge::ethernet_header_t::consume(buf);
    netforge::ipv4_header_t ip = netforge::ipv4_header_t::consume(buf);
    netforge::udp_header_t udp = netforge::udp_header_t::consume(buf);
    if (udp.dst_port == 53) {
        netforge::dns_message_t msg = netforge::dns_message_t::consume(buf);
        for (const auto& q : msg.questions)
            std::printf("question: %s\n", q.qname.c_str());
    }
}
```

## Quick start (Python)

```python
import netforge

ip = netforge.Ipv4Header()
ip.source_ip = 0x7F000001
ip.destination_ip = 0x7F000001
ip.protocol = 17

udp = netforge.UdpHeader()
udp.src_port = 53000
udp.dst_port = 53

pkt = netforge.Packet()
pkt.add(netforge.EthernetHeader())
pkt.add(ip)
pkt.add(udp)
pkt.add(netforge.make_dns_query("google.com"))

frame = pkt.data()          # 46-byte DNS query frame
ipv4, udp, dns = pkt.read_ipv4(), pkt.read_udp(), pkt.read_dns()
```

## Examples

| Target / script | What it does |
| --- | --- |
| `example_craft` | Crafts an eth/IPv4/UDP/DNS query and sends it raw on an interface |
| `example_dns_query` | Resolves a name over a normal UDP socket |
| `example_sniff` | Captures on an interface, dissecting each frame live |
| `example_tcp_handshake` | Parses the real SYN/SYN-ACK/ACK of a kernel handshake |
| `python/craft.py`, `python/dns_query.py`, `python/sniff.py` | Same, from Python |

Crafting/sending and capturing need root. Raw TCP on loopback is kernel-hijacked, so
`tcp_handshake` observes a real connection rather than injecting one — details in
[docs/examples.md](docs/examples.md).

## Benchmarks

Same 42-byte ethernet/IPv4/UDP frame, `benchmarks/bench_parse.cpp` (C++),
`benchmarks/bench_bindings.py`, `benchmarks/bench_scapy.py`:

| Implementation | Parse (ns/op) | Parse (Mpps) | Build (ns/op) | Build (Mpps) |
|---|--:|--:|--:|--:|
| Scapy (Python) | ~122,000 | 0.008 | ~313,000 | 0.003 |
| netforge Python bindings | ~8,000 | 0.12 | ~8,500 | 0.12 |
| netforge C++ core | ~190 | ~5.3 | ~330 | ~3.1 |

C++ core is ~650x (parse) and ~960x (build) faster than Scapy; even from Python the
bindings are ~15x–37x faster.

## Layout

```
include/netforge/
  buffer/   buffer cursor + byte-order/checksum utilities
  layers/   protocol header structs (produce/consume/checksum)
  io/       raw_socket (AF_PACKET), sniffer (libpcap), list_interfaces
  packet/   composite packet builder
  parser/   checksum + one-pass dissector
src/        implementations
bindings/   pybind11 module (_netforge)
python/     netforge package
examples/   cpp + python examples
tests/      ctest unit tests (ethernet, ipv4, tcp, dns, checksum)
benchmarks/ parse/build + scapy + binding comparison
docs/       architecture.md, examples.md, protocols.md
```

## License

MIT — see [LICENSE](LICENSE).