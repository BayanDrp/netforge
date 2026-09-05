#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <unistd.h>

#include <poll.h>
#include <sys/socket.h>

#include "netforge/buffer/buffer.hpp"
#include "netforge/io/sniffer.hpp"
#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/tcp.hpp"

using namespace netforge;

static const uint16_t kPort = static_cast<uint16_t>(30000 + (getpid() % 20000));

int main() {
    int lsock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(kPort);
    bind(lsock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    listen(lsock, 1);

    sniffer sn("lo", "tcp port " + std::to_string(kPort));

    std::thread client([&] {
        usleep(200000);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        close(c);
    });

    std::cout << "server listening on 127.0.0.1:" << kPort
              << ", sniffing the three-way handshake\n";

    uint8_t* data = nullptr;
    std::size_t len = 0;
    int seen = 0;
    for (int tries = 0; tries < 200 && seen < 3; ++tries) {
        if (!sn.next(data, len)) continue;
        try {
            buffer b(data, len);
            ethernet_header_t eth = ethernet_header_t::consume(b);
            if (eth.ethertype != 0x0800) continue;
            ipv4_header_t ip = ipv4_header_t::consume(b);
            if (ip.protocol != 6) continue;
            tcp_header_t tcp = tcp_header_t::consume(b);

            if (tcp.SYN && !tcp.ACK) {
                std::cout << "1. SYN       from " << ((ip.source_ip >> 24) & 0xFF) << "."
                          << ((ip.source_ip >> 16) & 0xFF) << "." << ((ip.source_ip >> 8) & 0xFF)
                          << "." << (ip.source_ip & 0xFF) << ":" << tcp.src_port
                          << " seq=" << tcp.seq_no << "\n";
                ++seen;
            } else if (tcp.SYN && tcp.ACK) {
                std::cout << "2. SYN-ACK   from " << ip.source_ip << ":" << tcp.src_port
                          << " seq=" << tcp.seq_no << " ack=" << tcp.ack_no << "\n";
                ++seen;
            } else if (tcp.ACK && !tcp.SYN) {
                std::cout << "3. ACK       from " << ip.source_ip << ":" << tcp.src_port
                          << " seq=" << tcp.seq_no << " ack=" << tcp.ack_no << "\n";
                ++seen;
            }
        } catch (const std::out_of_range&) {
        }
    }
    client.join();

    int cs = accept(lsock, nullptr, nullptr);
    close(cs);
    close(lsock);

    if (seen == 3) {
        std::cout << "captured the full three-way handshake for " << kPort << "\n";
        return 0;
    }
    std::cout << "captured " << seen << " of 3 handshake frames\n";
    return 1;
}