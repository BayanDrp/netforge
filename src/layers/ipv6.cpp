#include "netforge/layers/ipv6.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace netforge {

void ipv6_header_t::produce(buffer& buf) const {
    buf.produce<uint32_t>(
        (static_cast<uint32_t>(version) << 28) |
        (static_cast<uint32_t>(traffic_class) << 20) |
        (flow_label & 0xFFFFF));
    buf.produce<uint16_t>(payload_length);
    buf.produce<uint8_t>(next_header);
    buf.produce<uint8_t>(hop_limit);
    buf.produce_bytes(source_addr, 16);
    buf.produce_bytes(destination_addr, 16);
}

ipv6_header_t ipv6_header_t::consume(buffer& buf) {
    ipv6_header_t h;
    uint32_t word = buf.consume<uint32_t>();
    h.version = (word >> 28) & 0xF;
    h.traffic_class = (word >> 20) & 0xFF;
    h.flow_label = word & 0xFFFFF;
    h.payload_length = buf.consume<uint16_t>();
    h.next_header = buf.consume<uint8_t>();
    h.hop_limit = buf.consume<uint8_t>();
    std::memcpy(h.source_addr, buf.consume_bytes(16), 16);
    std::memcpy(h.destination_addr, buf.consume_bytes(16), 16);
    return h;
}

std::ostream& operator<<(std::ostream& out, const ipv6_header_t& h) {
    auto addr = [](const uint8_t a[16]) {
        std::ostringstream ss;
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) ss << ':';
            ss << std::hex << ((a[i] << 8) | a[i + 1]);
        }
        return ss.str();
    };
    out << "[IPv6] ";
    out << addr(h.source_addr) << " -> " << addr(h.destination_addr);
    out << " NEXT:" << (int)h.next_header;
    out << " HOP:" << (int)h.hop_limit;
    out << " PAYLOAD:" << h.payload_length;
    out << " FLOW:" << h.flow_label;
    return out;
}

}  // namespace netforge