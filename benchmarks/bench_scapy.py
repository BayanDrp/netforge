import time

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

N = 100000

eth = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00", type=0x0800)
ip = IP(proto=17, ttl=64, src="127.0.0.1", dst="127.0.0.1")
udp = UDP(sport=53000, dport=53, len=8, chksum=0)
frame_bytes = bytes(eth / ip / udp)
assert len(frame_bytes) == 42


def bench_build():
    t0 = time.perf_counter()
    for _ in range(N):
        pkt = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00", type=0x0800) / IP(
            proto=17, ttl=64, src="127.0.0.1", dst="127.0.0.1"
        ) / UDP(sport=53000, dport=53, len=8, chksum=0)
        b = bytes(pkt)
    t1 = time.perf_counter()
    return (t1 - t0) * 1e9 / N, N / (t1 - t0) / 1e6


def bench_parse():
    sink = 0
    t0 = time.perf_counter()
    for _ in range(N):
        p = Ether(frame_bytes)
        sink += p[IP].src == "127.0.0.1"
    t1 = time.perf_counter()
    return (t1 - t0) * 1e9 / N, N / (t1 - t0) / 1e6, sink


b_ns, b_mpps = bench_build()
p_ns, p_mpps, sink = bench_parse()

print(f"frame size: {len(frame_bytes)} bytes")
print(f"scapy build:  {b_ns:8.1f} ns/op  ({b_mpps:7.2f} Mpps)")
print(f"scapy parse:  {p_ns:8.1f} ns/op  ({p_mpps:7.2f} Mpps)")
print(f"(sink {sink})")