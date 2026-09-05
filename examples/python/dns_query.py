import socket
import sys

import netforge

host = sys.argv[1] if len(sys.argv) > 1 else "google.com"
server = ("8.8.8.8", 53)

msg = netforge.DnsMessage()
msg.header.id = 0x1337
msg.header.rd = 1
msg.add_question(host, qtype=1, qclass=1)
query = msg.to_bytes()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(query, server)
data, _ = sock.recvfrom(2048)

reply = netforge.DnsMessage.from_bytes(data)
print(f"{host}: {len(query)}B query, {len(data)}B reply, {len(reply.answers)} answers")
for a in reply.answers:
    if a.type == 1 and len(a.rdata) == 4:
        ip = ".".join(str(b) for b in a.rdata)
        print(f"  A {a.name} -> {ip} (ttl {a.ttl})")