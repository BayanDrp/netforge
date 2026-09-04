#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/layers/dns.hpp"

using netforge::buffer;
using netforge::dns_message_t;

static std::string rdata_to_string(const std::vector<uint8_t>& rdata) {
    std::string out;
    for (uint8_t b : rdata) {
        if (!out.empty()) out += '.';
        out += std::to_string(b);
    }
    return out;
}

int main(int argc, char* argv[]) {
    const char* hostname = argc > 1 ? argv[1] : "google.com";
    const char* resolver = argc > 2 ? argv[2] : "8.8.8.8";

    dns_message_t query;
    query.header.id = 0x1234;
    query.header.rd = 1;
    dns_message_t::question_t q;
    q.qname = hostname;
    q.qtype = 1;
    q.qclass = 1;
    query.questions.push_back(q);

    std::vector<uint8_t> wire(512);
    buffer out(wire.data(), wire.size());
    query.produce(out);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::perror("socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    if (inet_pton(AF_INET, resolver, &addr.sin_addr) != 1) {
        std::fprintf(stderr, "invalid resolver: %s\n", resolver);
        return 1;
    }

    ssize_t sent = sendto(fd, wire.data(), out.position(), 0,
                          reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (sent < 0) {
        std::perror("sendto");
        return 1;
    }

    std::vector<uint8_t> reply(4096);
    socklen_t alen = sizeof(addr);
    ssize_t got = recvfrom(fd, reply.data(), reply.size(), 0,
                           reinterpret_cast<sockaddr*>(&addr), &alen);
    close(fd);
    if (got < 0) {
        std::perror("recvfrom");
        return 1;
    }

    std::printf("sent %zd bytes to %s:53 for %s\n", sent, resolver, hostname);

    auto recv_buf = reply.data();
    buffer in(recv_buf, static_cast<size_t>(got));
    dns_message_t response = dns_message_t::consume(in);

    std::printf("rcode=%u qd=%u an=%u ns=%u ar=%u\n",
                response.header.rcode, response.header.qdcount,
                response.header.ancount, response.header.nscount,
                response.header.arcount);
    for (const auto& ans : response.answers) {
        std::printf("  %-3u %-8u %s\n", ans.type, ans.ttl,
                    rdata_to_string(ans.rdata).c_str());
    }
    return 0;
}