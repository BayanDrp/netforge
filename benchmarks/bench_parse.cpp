#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/udp.hpp"
#include "netforge/packet/packet.hpp"

using namespace netforge;
using clk = std::chrono::steady_clock;

static constexpr int kIters = 200000;

int main() {
    ethernet_header_t eth;
    std::memset(eth.dst_mac, 0, 6);
    std::memset(eth.src_mac, 0, 6);
    eth.ethertype = 0x0800;

    ipv4_header_t ip;
    ip.protocol = 17;
    ip.source_ip = 0x7F000001;
    ip.destination_ip = 0x7F000001;
    ip.total_length = 28;
    ip.compute_checksum();

    udp_header_t udp;
    udp.src_port = 53000;
    udp.dst_port = 53;
    udp.length = 8;
    udp.checksum = 0;

    packet pkt;
    pkt.add(eth);
    pkt.add(ip);
    pkt.add(udp);
    const std::size_t wire_len = pkt.size();
    std::vector<uint8_t> wire(pkt.data(), pkt.data() + wire_len);

    auto t0 = clk::now();
    std::size_t sink = 0;
    for (int i = 0; i < kIters; ++i) {
        buffer in(wire.data(), wire_len);
        ethernet_header_t e = ethernet_header_t::consume(in);
        ipv4_header_t p = ipv4_header_t::consume(in);
        udp_header_t u = udp_header_t::consume(in);
        sink += e.ethertype + p.source_ip + u.dst_port;
    }
    auto t1 = clk::now();
    double parse_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / kIters;

    auto t2 = clk::now();
    for (int i = 0; i < kIters; ++i) {
        packet q;
        q.add(eth);
        q.add(ip);
        q.add(udp);
        sink += q.size() + q.data()[0];
    }
    auto t3 = clk::now();
    double build_ns = std::chrono::duration<double, std::nano>(t3 - t2).count() / kIters;

    std::printf("frame size: %zu bytes\n", wire_len);
    std::printf("parse:  %8.1f ns/op  (%7.2f Mpps)\n", parse_ns, 1000.0 / parse_ns);
    std::printf("build:  %8.1f ns/op  (%7.2f Mpps)\n", build_ns, 1000.0 / build_ns);
    std::printf("(sink %zu)\n", sink);
    return 0;
}