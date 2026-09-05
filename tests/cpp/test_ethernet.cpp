#include <cstdint>
#include <cstring>
#include <sstream>

#include "netforge/buffer/buffer.hpp"
#include "netforge/layers/ethernet.hpp"

#include "test_util.hpp"

using namespace netforge;

int main() {
    ethernet_header_t h;
    CHECK(h.size() == 14);
    CHECK(h.ethertype == 0);

    const uint8_t dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t src[6] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x02};
    std::memcpy(h.dst_mac, dst, 6);
    std::memcpy(h.src_mac, src, 6);
    h.ethertype = 0x0800;

    uint8_t wire[14];
    buffer out(wire, sizeof(wire));
    h.produce(out);
    CHECK(out.position() == 14);
    CHECK(wire[0] == 0xff && wire[5] == 0xff);
    CHECK(wire[6] == 0x02 && wire[7] == 0x42);
    CHECK(wire[12] == 0x08 && wire[13] == 0x00);

    buffer in(wire, sizeof(wire));
    ethernet_header_t back = ethernet_header_t::consume(in);
    CHECK(back.ethertype == 0x0800);
    CHECK(in.position() == 14);
    CHECK(std::memcmp(back.dst_mac, dst, 6) == 0);
    CHECK(std::memcmp(back.src_mac, src, 6) == 0);

    std::ostringstream ss;
    ss << back;
    CHECK(!ss.str().empty());
    DONE();
}