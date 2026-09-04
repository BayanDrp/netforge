#include "netforge/layers/ethernet.hpp"

#include <cstring>
#include <iomanip>

namespace netforge {

void ethernet_header_t::produce(buffer& buf) {
    buf.produce_bytes(dst_mac, 6);
    buf.produce_bytes(src_mac, 6);
    buf.produce<uint16_t>(ethertype);
}

ethernet_header_t ethernet_header_t::consume(buffer& buf) {
    ethernet_header_t hdr;
    std::memcpy(hdr.dst_mac, buf.consume_bytes(6), 6);
    std::memcpy(hdr.src_mac, buf.consume_bytes(6), 6);
    hdr.ethertype = buf.consume<uint16_t>();
    return hdr;
}

std::ostream& operator<<(std::ostream& out, const ethernet_header_t& h) {
    out << "Ethernet: dst=";
    for (int i = 0; i < 6; ++i) {
        if (i > 0) out << ":";
        out << std::hex << std::setw(2) << std::setfill('0') << (int)h.dst_mac[i];
    }
    out << " src=";
    for (int i = 0; i < 6; ++i) {
        if (i > 0) out << ":";
        out << std::hex << std::setw(2) << std::setfill('0') << (int)h.src_mac[i];
    }
    out << " ethertype=0x" << std::hex << h.ethertype;
    return out;
}

}  // namespace netforge