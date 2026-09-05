import signal
import sys

import netforge

filter_expr = sys.argv[1] if len(sys.argv) > 1 else "udp port 53"
dev = sys.argv[2] if len(sys.argv) > 2 else "lo"

print("interfaces:", ", ".join(netforge.list_interfaces()))
sniffer = netforge.Sniffer(dev, filter_expr)
print(f"capturing on {dev} with filter '{filter_expr}' (Ctrl-C to stop)")

signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

while True:
    raw = sniffer.next()
    if raw is None:
        continue
    eth = netforge.EthernetHeader.from_bytes(raw)
    print(f"{len(raw):4} bytes  eth 0x{eth.ethertype:04x}")
    if eth.ethertype == 0x0800:
        ip = netforge.Ipv4Header.from_bytes(raw[14:34])
        print(f"           ipv4 ttl={ip.ttl} proto={ip.protocol} "
              f"{netforge.ipv4_to_string(ip.source_ip)} -> "
              f"{netforge.ipv4_to_string(ip.destination_ip)}")
        if ip.protocol == 17 and len(raw) >= 42:
            udp = netforge.UdpHeader.from_bytes(raw[34:42])
            print(f"           udp {udp.src_port} -> {udp.dst_port}")
            if udp.dst_port == 53 or udp.src_port == 53:
                dns = netforge.DnsMessage.from_bytes(raw[42:])
                for q in dns.questions:
                    print(f"           dns q: {q.qname}")