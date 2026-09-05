# netforge — supported protocols

All multi-byte fields are serialized big-endian on the wire; header objects store
numeric fields in host order.

## Ethernet (14 bytes)

- `dst_mac[6]`, `src_mac[6]`, `ethertype`

## IPv4 (20 bytes)

- `version` (default 4), `ihl` (default 5), `dscp`, `ecn`
- `total_length`, `identification`, `flags`, `fragment_offset`
- `ttl` (default 64), `protocol`, `header_checksum`, `source_ip`, `destination_ip`
- `compute_checksum()` fills `header_checksum` over the header.

## IPv6 (40 bytes)

- `version` (default 6), `traffic_class`, `flow_label`
- `payload_length` (excludes the fixed header), `next_header`, `hop_limit`
- 16-byte `source_ip`/`destination_ip`
- No checksum (per RFC 8200).

## UDP (8 bytes)

- `src_port`, `dst_port`, `length`, `checksum`
- `compute_checksum(src, dst, payload, len)` covers the UDP header + payload via the
  IPv4 pseudo-header.

## TCP (20 bytes)

- `src_port`, `dst_port`, `seq_no`, `ack_no`
- `header_length` (default 5), reserved, flags as named booleans
  (`URG ACK PSH RST SYN FIN`)
- `window_size`, `checksum`, `urgent_pointer`
- `compute_checksum(src, dst, payload, len)` covers the header + options + payload via
  the IPv4 pseudo-header.

## ICMP (8 bytes)

- `type`, `code`, `checksum`, `identifier`, `sequence`
- `compute_checksum(payload, len)` covers the header + payload (no pseudo-header).

## DNS

- `dns_header_t`: `id`, `qr`, `opcode`, `aa`, `tc`, `rd`, `ra`, `z`, `rcode`,
  `qdcount`, `ancount`, `nscount`, `arcount`.
- `dns_message_t`: `header`, `questions`, `answers`; `produce()` auto-fills the
  question/answer counts from vector sizes.
- `encode_name()`/`decode_name()` handle dotted names; `consume()` resolves
  compression pointers (e.g. `0xC00C`).

## HTTP

- Header storage types; see `include/netforge/layers/http.hpp`.

## Checksum invariant

For any serialized IPv4 header, TCP segment, UDP datagram, or ICMP message with its
checksum field populated, `utils::checksum(data, len, start)` returns `0`.

## Layer walking

`parser::dissect_frame()` handles ethernet → ipv4/ipv6 → udp/tcp/icmp/icmpv6 in one
pass, sets `ipv4_checksum_ok`, `tcp_checksum_ok`, `udp_checksum_ok`, and points
`payload`/`payload_len` past the L4 header.