#ifndef NETFORGE_LAYERS_ETHERNET_HPP
#define NETFORGE_LAYERS_ETHERNET_HPP

#include <cstdint>
#include <ostream>

#include "netforge/buffer/buffer.hpp"

namespace netforge {

struct ethernet_header_t {
    uint8_t dst_mac[6]{};
    uint8_t src_mac[6]{};
    uint16_t ethertype{0};

    static constexpr size_t size() { return 14; }

    void produce(buffer& buf);
    static ethernet_header_t consume(buffer& buf);

    friend std::ostream& operator<<(std::ostream& out, const ethernet_header_t& h);
};

}  // namespace netforge

#endif  // NETFORGE_LAYERS_ETHERNET_HPP