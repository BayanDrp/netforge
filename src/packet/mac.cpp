#include "netforge/packet/mac.hpp"

#include <iomanip>
#include <sstream>

namespace netforge {

namespace {

bool hex_digit(char c, unsigned& value) {
    if (c >= '0' && c <= '9') {
        value = static_cast<unsigned>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        value = static_cast<unsigned>(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        value = static_cast<unsigned>(c - 'A' + 10);
        return true;
    }
    return false;
}

}  // namespace

mac_t mac_t::from_string(const char* str) {
    if (!str) return mac_t::zero();

    mac_t m;
    const char* p = str;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            if (*p != ':') return mac_t::zero();
            ++p;
        }
        unsigned hi = 0;
        unsigned lo = 0;
        if (!hex_digit(*p, hi) || !hex_digit(*(p + 1), lo))
            return mac_t::zero();
        m.addr[i] = static_cast<uint8_t>((hi << 4) | lo);
        p += 2;
    }
    if (*p != '\0') return mac_t::zero();
    return m;
}

std::string mac_t::to_string() const {
    std::ostringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ':';
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned>(addr[i]);
    }
    return ss.str();
}

}  // namespace netforge