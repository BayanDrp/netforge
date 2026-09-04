#include "netforge/layers/ethernet.hpp"

#include "netforge/buffer/utils.hpp"
#include <cstring>
#include <iomanip>

namespace netforge {

void ethernet_header_t::produce(uint8_t*& ptr) {
    memcpy(ptr, dst_mac, 6);
    ptr += 6;
    memcpy(ptr, src_mac, 6);
    ptr += 6;
    utils::produce<uint16_t>(ptr, ethertype);
}

ethernet_header_t ethernet_header_t::consume(uint8_t*& ptr) {
    ethernet_header_t hdr;
    memcpy(hdr.dst_mac, ptr, 6);
    ptr += 6;
    memcpy(hdr.src_mac, ptr, 6);
    ptr += 6;
    hdr.ethertype = utils::consume<uint16_t>(ptr);
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