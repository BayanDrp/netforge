#include <cstdio>
#include <cstring>
#include <vector>

#include "netforge/io/raw_socket.hpp"
#include "netforge/layers/dns.hpp"
#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/udp.hpp"
#include "netforge/packet/packet.hpp"

using namespace netforge;

int main(int argc, char* argv[]) {
    const char* hostname = argc > 1 ? argv[1] : "google.com";
    const char* iface = argc > 2 ? argv[2] : "lo";

    dns_message_t dns;
    dns.header.id = 0x1337;
    dns.header.rd = 1;
    dns_message_t::question_t q;
    q.qname = hostname;
    q.qtype = 1;
    q.qclass = 1;
    dns.questions.push_back(q);

    std::vector<uint8_t> dns_wire(512);
    buffer dns_buf(dns_wire.data(), dns_wire.size());
    dns.produce(dns_buf);
    uint16_t udp_len = static_cast<uint16_t>(8 + dns_buf.position());

    udp_header_t udp;
    udp.src_port = 53000;
    udp.dst_port = 53;
    udp.length = udp_len;
    udp.checksum = 0;

    ipv4_header_t ip;
    ip.protocol = 17;
    ip.ttl = 64;
    ip.source_ip = 0x7F000001;
    ip.destination_ip = 0x7F000001;
    ip.total_length = static_cast<uint16_t>(20 + udp_len);
    ip.compute_checksum();

    ethernet_header_t eth;
    std::memset(eth.dst_mac, 0, 6);
    std::memset(eth.src_mac, 0, 6);
    eth.ethertype = 0x0800;

    packet pkt;
    pkt.add(eth);
    pkt.add(ip);
    pkt.add(udp);
    pkt.add(dns);

    std::printf("crafted DNS query for %s: %zu bytes total\n", hostname, pkt.size());

    raw_socket sock(iface);
    ssize_t sent = sock.send(pkt.data(), pkt.size());
    std::printf("sent (AF_PACKET): %zd/%zu bytes on %s\n", sent, pkt.size(), iface);
    return sent > 0 ? 0 : 1;
}