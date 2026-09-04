#pragma once

#include <cstdint>
#include <ostream>

#include "netforge/buffer/buffer.hpp"

namespace netforge {

struct udp_header_t {
    using port_addr_t = uint16_t;

    port_addr_t src_port;
    port_addr_t dst_port;
    uint16_t length;
    uint16_t checksum;

    static constexpr size_t size() { return 8; }

    udp_header_t();

    void produce(buffer& buf) const;
    static udp_header_t consume(buffer& buf);

    friend std::ostream& operator<<(std::ostream& out, const udp_header_t& h);
};

}  // namespace netforge