import sys

import netforge

host = sys.argv[1] if len(sys.argv) > 1 else "example.com"
iface = sys.argv[2] if len(sys.argv) > 2 else "lo"

frame = netforge.make_dns_query(host)
print(f"crafted DNS query for {host}: {len(frame)} bytes total")

raw = netforge.RawSocket(iface)
sent = raw.send(frame)
print(f"sent (AF_PACKET): {sent}/{len(frame)} bytes on {iface}")
sys.exit(0 if sent > 0 else 1)