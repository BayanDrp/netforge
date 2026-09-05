#include <cstdint>

#include "netforge/buffer/buffer.hpp"
#include "netforge/buffer/utils.hpp"
#include "netforge/layers/ipv4.hpp"

#include "test_util.hpp"

using namespace netforge;

int main() {
    ipv4_header_t h;
    CHECK(h.version == 4);
    CHECK(h.ihl == 5);
    CHECK(h.ttl == 64);
    CHECK(h.header_checksum == 0);

    h.dscp = 16;
    h.ecn = 2;
    h.total_length = 40;
    h.identification = 0x1234;
    h.flags = 2;
    h.fragment_offset = 100;
    h.protocol = 6;
    h.ttl = 42;
    h.source_ip = 0x7F000001;
    h.destination_ip = 0x7F000001;
    h.compute_checksum();
    CHECK(h.header_checksum != 0);

    uint8_t wire[20];
    buffer out(wire, sizeof(wire));
    h.produce(out);
    CHECK(out.position() == 20);
    CHECK((wire[0] >> 4) == 4 && (wire[0] & 0xF) == 5);
    CHECK(((wire[2] << 8) | wire[3]) == 40);

    CHECK(utils::checksum(wire, 20, 0) == 0);

    buffer in(wire, 20);
    ipv4_header_t back = ipv4_header_t::consume(in);
    CHECK(back.version == 4);
    CHECK(back.ihl == 5);
    CHECK(back.dscp == 16);
    CHECK(back.ecn == 2);
    CHECK(back.total_length == 40);
    CHECK(back.identification == 0x1234);
    CHECK(back.flags == 2);
    CHECK(back.fragment_offset == 100);
    CHECK(back.protocol == 6);
    CHECK(back.ttl == 42);
    CHECK(back.source_ip == 0x7F000001);
    CHECK(back.destination_ip == 0x7F000001);
    CHECK(back.header_checksum == h.header_checksum);
    CHECK(in.position() == 20);

    DONE();
}