#include <csignal>
#include <cstdio>
#include <iostream>
#include <stdexcept>

#include "netforge/io/sniffer.hpp"
#include "netforge/layers/dns.hpp"
#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/icmp.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/ipv6.hpp"
#include "netforge/layers/tcp.hpp"
#include "netforge/layers/udp.hpp"

using namespace netforge;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int) { g_stop = 1; }

int main(int argc, char* argv[]) {
    const char* dev = argc > 1 ? argv[1] : "lo";
    const char* filter = argc > 2 ? argv[2] : "";

    std::signal(SIGINT, on_signal);

    std::printf("interfaces:\n");
    for (const auto& name : list_interfaces()) std::printf("  %s\n", name.c_str());

    sniffer s(dev, filter);
    std::printf("capturing on %s with filter '%s' (Ctrl-C to stop)\n", dev, filter);

    uint8_t* data = nullptr;
    std::size_t len = 0;
    while (!g_stop) {
        if (!s.next(data, len)) return 1;
        std::printf("%4zu bytes  ", len);

        buffer in(data, len);
        try {
            ethernet_header_t eth = ethernet_header_t::consume(in);
            std::cout << eth;
            if (eth.ethertype == 0x0800) {
                ipv4_header_t ip = ipv4_header_t::consume(in);
                std::cout << "  " << ip;
                if (ip.protocol == 17) {
                    std::cout << "  " << udp_header_t::consume(in);
                } else if (ip.protocol == 6) {
                    std::cout << "  " << tcp_header_t::consume(in);
                } else if (ip.protocol == 1) {
                    std::cout << "  " << icmp_header_t::consume(in);
                }
            } else if (eth.ethertype == 0x86DD) {
                std::cout << "  " << ipv6_header_t::consume(in);
            }
        } catch (const std::out_of_range& ex) {
            std::printf("  (truncated frame: %s)", ex.what());
        }
        std::printf("\n");
    }
    return 0;
}