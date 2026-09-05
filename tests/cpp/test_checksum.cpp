#include <cstdint>
#include <cstring>
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/buffer/utils.hpp"
#include "netforge/layers/icmp.hpp"

#include "test_util.hpp"

using namespace netforge;

int main() {
    uint8_t one[] = {0xFF};
    CHECK(utils::checksum(one, 1, 0) == 0x00FF);

    uint8_t pair[] = {0xFF, 0xFF};
    CHECK(utils::checksum(pair, 2, 0) == 0x0000);

    uint8_t vals[] = {0x12, 0x34};
    CHECK(utils::checksum(vals, 2, 0) == 0xEDCB);

    uint8_t wrap[] = {0x01, 0x00};
    CHECK(utils::checksum(wrap, 2, 0xFFFF) == 0xFEFF);

    icmp_header_t icmp;
    icmp.type = 8;
    icmp.code = 0;
    icmp.identifier = 0x1234;
    icmp.sequence = 1;
    const uint8_t payload[] = {'n', 'e', 't', 'f', 'o', 'r', 'g', 'e'};
    icmp.compute_checksum(payload, static_cast<int>(sizeof(payload)));
    CHECK(icmp.checksum != 0);

    std::vector<uint8_t> wire(icmp.size() + sizeof(payload));
    buffer out(wire.data(), wire.size());
    icmp.produce(out);
    std::memcpy(wire.data() + icmp.size(), payload, sizeof(payload));
    CHECK(utils::checksum(wire.data(), static_cast<int>(wire.size()), 0) == 0);

    buffer in(wire.data(), wire.size());
    icmp_header_t back = icmp_header_t::consume(in);
    CHECK(back.type == 8);
    CHECK(back.code == 0);
    CHECK(back.identifier == 0x1234);
    CHECK(back.sequence == 1);
    CHECK(back.checksum == icmp.checksum);

    DONE();
}