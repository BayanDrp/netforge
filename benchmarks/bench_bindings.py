import time

import netforge

N = 100000


def make_eth():
    e = netforge.EthernetHeader()
    e.dst_mac = bytes(6)
    e.src_mac = bytes(6)
    e.ethertype = 0x0800
    return e


def make_ip():
    i = netforge.Ipv4Header()
    i.protocol = 17
    i.ttl = 64
    i.source_ip = 0x7F000001
    i.destination_ip = 0x7F000001
    i.total_length = 28
    i.compute_checksum()
    return i


def make_udp():
    u = netforge.UdpHeader()
    u.src_port = 53000
    u.dst_port = 53
    u.length = 8
    u.checksum = 0
    return u


eth = make_eth()
ip = make_ip()
udp = make_udp()


def bench_build():
    t0 = time.perf_counter()
    for _ in range(N):
        p = netforge.Packet()
        p.add(eth)
        p.add(ip)
        p.add(udp)
        p.size()
    t1 = time.perf_counter()
    return (t1 - t0) * 1e9 / N, N / (t1 - t0) / 1e6


def bench_parse():
    sink = 0
    t0 = time.perf_counter()
    for _ in range(N):
        p = netforge.Packet()
        p.add(eth)
        p.add(ip)
        p.add(udp)
        e = p.read_ethernet()
        i = p.read_ipv4()
        u = p.read_udp()
        sink += u.dst_port
    t1 = time.perf_counter()
    return (t1 - t0) * 1e9 / N, N / (t1 - t0) / 1e6, sink


b_ns, b_mpps = bench_build()
p_ns, p_mpps, sink = bench_parse()

print(f"frame size: 42 bytes")
print(f"netforge(bindings) build:  {b_ns:8.1f} ns/op  ({b_mpps:7.2f} Mpps)")
print(f"netforge(bindings) parse:  {p_ns:8.1f} ns/op  ({p_mpps:7.2f} Mpps)")
print(f"(sink {sink})")