# netforge — architecture

`netforge` is a header-driven packet crafting and parsing library written in C++17,
with zero external runtime dependencies for the core library (libpcap is optional and
used only by the sniffer).

## Layout

```
include/netforge/
  buffer/       byte buffer cursor + endianness/checksum helpers
  io/           raw socket (AF_PACKET) and pcap sniffer
  layers/       protocol header types (ethernet, ipv4, ipv6, udp, tcp, icmp, dns, http)
  packet/       composition container that serializes chains of layers
  parser/       one-shot dissector + checksum verification over a captured frame
src/
  buffer/ layers/ io/ packet/ parser/   matching .cpp implementations
bindings/       pybind11 Python module (built only if pybind11 is installed)
python/         `netforge` package shim (imports the compiled `_netforge` module)
examples/       runnable C++ and Python examples
tests/          CTest unit tests
benchmarks/     microbenchmarks
```

## Design decisions

- **Header-driven.** Each layer type owns its fields in native/host memory order. The
  header object is the source of truth; `produce()`/`consume()` translate to/from the
  wire format with explicit byte-order conversion. Iterating on a header is compile-time
  checked; garbage in a capture fails with `std::out_of_range` instead of memory errors.

- **Buffer cursor.** `buffer` is a thin cursor over a caller-owned byte region, so the
  library never allocates during parsing. Layers read with bounds checks; over-reading
  throws `out_of_range`.

- **Checksums computed at `produce` time via `compute_checksum()`; restored/verified on
  parse via `utils::checksum`.** The ipv4 header checksum covers the 20-byte header.
  TCP/UDP checksums include the 12-byte IPv4 pseudo-header (source, destination, zero,
  protocol, length). A header serialized with its checksum field set verifies to zero.

- **Composition.** `netforge::packet` chains layers: `pkt.add(eth); pkt.add(ip);
  pkt.add(udp); pkt.add(dns);` then `pkt.data()`/`pkt.size()` give the full frame.

- **Digestion.** `parser::dissect_frame(data, len, out)` walks a raw capture once and
  fills a `dissected_packet` with the parsed ethernet/ipv4/ipv6/udp/tcp/icmp headers,
  a pointer to the payload, and per-protocol checksum validity flags.

- **Raw vs. normal sockets.** `raw_socket` uses `AF_PACKET`/`SOCK_RAW` and requires
  root. It can send onto any interface, but the kernel is free to drop or ignore
  packets it judges foreign (notably raw TCP on loopback), so it is best used for
  crafted frames the kernel is not expected to accept.