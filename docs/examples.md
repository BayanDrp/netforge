# netforge — examples

All commands assume a built tree: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release &&
cmake --build build`. Examples that send or capture on an interface need root.

## C++ examples

| Target | Source | What it does |
| --- | --- | --- |
| `example_craft` | `examples/cpp/craft.cpp` | Crafts an ethernet/IPv4/UDP/DNS query for a hostname and sends it raw on an interface |
| `example_dns_query` | `examples/cpp/dns_query.cpp` | Builds a DNS query and parses the reply via a normal UDP socket |
| `example_sniff` | `examples/cpp/sniff.cpp` | Lists interfaces, then captures on one, dissecting each ethernet/IPv4/IPv6/UDP/TCP/ICMP frame as it arrives |
| `example_tcp_handshake` | `examples/cpp/tcp_handshake.cpp` | Starts a real TCP server, connects with a normal client, and demonstrates parsing the three-way handshake (SYN / SYN-ACK / ACK) with seq/ack bookkeeping |

Run as `sudo ./build/example_craft lo`, `sudo ./build/example_sniff lo "udp port 53"`, etc.

### Capturing a handshake

```
server listening on 127.0.0.1:31231, sniffing the three-way handshake
1. SYN       from 127.0.0.1:43096 seq=3984091016
2. SYN-ACK   from 2130706433:31231 seq=2124037456 ack=3984091017
3. ACK       from 2130706433:43096 seq=3984091017 ack=2124037457
captured the full three-way handshake for 31231
```

## Python examples

With bindings built (`pip install -e . --break-system-packages`):

| Script | What it does |
| --- | --- |
| `examples/python/craft.py IFACE` | Sends a crafted DNS query on an interface |
| `examples/python/dns_query.py` | Resolves a name via `make_dns_query` over a normal UDP socket |
| `examples/python/sniff.py IFACE FILTER` | Captures on an interface and prints each packet with its parsed layers |

Example:

```
$ sudo python examples/python/sniff.py lo "udp port 53"
  ...craft a DNS query on another shell...
eth -> ipv4 127.0.0.1 -> 127.0.0.1 udp 53000 -> 53 dns q: example.com
```

## Notes on raw sending

- Raw senders (`AF_PACKET`) require root.
- On `lo`, the kernel processes raw frames addressed to local IPs and may drop,
  rewrite, or answer them — a raw SYN to a listening loopback port is not a reliable
  way to open a real connection. Use raw crafting for netbios-style injection and the
  sniffer to observe the kernel's generated traffic, or craft to non-loopback
  destinations on real NICs.