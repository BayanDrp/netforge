#pragma once

#include <cstdint>
#include <ostream>

namespace netforge {

struct ethernet_header_t {
    uint8_t dst_mac[6]{};
    uint8_t src_mac[6]{};
    uint16_t ethertype{0};

    static constexpr size_t size() { return 14; }

    void produce(uint8_t*& ptr);
    static ethernet_header_t consume(uint8_t*& ptr);

    friend std::ostream& operator<<(std::ostream& out, const ethernet_header_t& h);
};

}  // namespace netforge