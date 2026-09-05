#ifndef NETFORGE_PACKET_MAC_HPP
#define NETFORGE_PACKET_MAC_HPP

#include <cstdint>
#include <cstring>
#include <string>

namespace netforge {

struct mac_t {
    uint8_t addr[6]{};

    mac_t() = default;
    mac_t(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f)
        : addr{a, b, c, d, e, f} {}

    bool operator==(const mac_t& o) const { return std::memcmp(addr, o.addr, 6) == 0; }
    bool operator!=(const mac_t& o) const { return !(*this == o); }

    static mac_t from_string(const char* str);
    std::string to_string() const;

    static mac_t broadcast() { return mac_t(0xff, 0xff, 0xff, 0xff, 0xff, 0xff); }
    static mac_t zero() { return mac_t(); }
};

}  // namespace netforge

#endif  // NETFORGE_PACKET_MAC_HPP