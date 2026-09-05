#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/buffer/utils.hpp"
#include "netforge/layers/tcp.hpp"

#include "test_util.hpp"

using namespace netforge;

int main() {
    tcp_header_t t;
    CHECK(t.header_length == 5);
    CHECK(t.checksum == 0);

    t.src_port = 53000;
    t.dst_port = 53;
    t.seq_no = 0xDEADBEEF;
    t.ack_no = 0x11223344;
    t.SYN = 1;
    t.ACK = 1;
    t.RST = 0;
    t.FIN = 0;
    t.PSH = 0;
    t.URG = 0;
    t.window_size = 64240;
    t.urgent_pointer = 0;

    const char payload[] = "GET / HTTP/1.0\r\n\r\n";
    const uint32_t src = 0x7F000001;
    const uint32_t dst = 0x7F000001;
    t.compute_checksum(src, dst, reinterpret_cast<const uint8_t*>(payload),
                       static_cast<int>(std::strlen(payload)));
    CHECK(t.checksum != 0);

    std::vector<uint8_t> wire(20 + std::strlen(payload));
    buffer out(wire.data(), wire.size());
    t.produce(out);
    CHECK(wire[12] == 0x50 && wire[13] == 0x12);
    std::memcpy(wire.data() + 20, payload, std::strlen(payload));

    uint8_t pseudo[12];
    uint32_t nsrc = htonl(src);
    uint32_t ndst = htonl(dst);
    std::memcpy(pseudo, &nsrc, 4);
    std::memcpy(pseudo + 4, &ndst, 4);
    pseudo[8] = 0;
    pseudo[9] = 6;
    uint16_t nlen = htons(static_cast<uint16_t>(wire.size()));
    std::memcpy(pseudo + 10, &nlen, 2);
    uint32_t sum = utils::sum_every_16bits(pseudo, 12);
    CHECK(utils::checksum(wire.data(), static_cast<int>(wire.size()), sum) == 0);

    buffer in(wire.data(), 20);
    tcp_header_t back = tcp_header_t::consume(in);
    CHECK(back.src_port == 53000);
    CHECK(back.dst_port == 53);
    CHECK(back.seq_no == 0xDEADBEEF);
    CHECK(back.ack_no == 0x11223344);
    CHECK(back.SYN == 1);
    CHECK(back.ACK == 1);
    CHECK(back.RST == 0);
    CHECK(back.FIN == 0);
    CHECK(back.PSH == 0);
    CHECK(back.URG == 0);
    CHECK(back.header_length == 5);
    CHECK(back.window_size == 64240);
    CHECK(back.checksum == t.checksum);
    CHECK(in.position() == 20);

    DONE();
}