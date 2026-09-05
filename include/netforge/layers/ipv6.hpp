#ifndef NETFORGE_LAYERS_IPV6_HPP
#define NETFORGE_LAYERS_IPV6_HPP

#include <cstdint>
#include <ostream>

#include "netforge/buffer/buffer.hpp"

namespace netforge {

struct ipv6_header_t {
    uint8_t version = 6;
    uint8_t traffic_class = 0;
    uint32_t flow_label = 0;

    uint16_t payload_length = 0;
    uint8_t next_header = 0;
    uint8_t hop_limit = 64;

    uint8_t source_addr[16]{};
    uint8_t destination_addr[16]{};

    static constexpr size_t size() { return 40; }

    void produce(buffer& buf) const;
    static ipv6_header_t consume(buffer& buf);

    friend std::ostream& operator<<(std::ostream& out, const ipv6_header_t& h);
};

}  // namespace netforge

#endif  // NETFORGE_LAYERS_IPV6_HPP