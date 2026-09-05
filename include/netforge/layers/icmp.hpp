#ifndef NETFORGE_LAYERS_ICMP_HPP
#define NETFORGE_LAYERS_ICMP_HPP

#include <cstdint>
#include <ostream>

#include "netforge/buffer/buffer.hpp"

namespace netforge {

struct icmp_header_t {
    uint8_t type = 8;
    uint8_t code = 0;
    uint16_t checksum = 0;
    uint16_t identifier = 0;
    uint16_t sequence = 0;

    static constexpr size_t size() { return 8; }

    void compute_checksum(const uint8_t* payload = nullptr, int payload_len = 0);

    void produce(buffer& buf) const;
    static icmp_header_t consume(buffer& buf);

    friend std::ostream& operator<<(std::ostream& out, const icmp_header_t& h);
};

}  // namespace netforge

#endif  // NETFORGE_LAYERS_ICMP_HPP