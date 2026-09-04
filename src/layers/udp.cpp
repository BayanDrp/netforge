#include "netforge/layers/udp.hpp"

#include "netforge/buffer/utils.hpp"

namespace netforge {

udp_header_t::udp_header_t() {
    src_port = 0;
    dst_port = 0;
    length = 0;
    checksum = 0;
}

void udp_header_t::produce(uint8_t*& ptr) const {
    utils::produce<port_addr_t>(ptr, src_port);
    utils::produce<port_addr_t>(ptr, dst_port);
    utils::produce<uint16_t>(ptr, length);
    utils::produce<uint16_t>(ptr, checksum);
}

udp_header_t udp_header_t::consume(uint8_t*& ptr) {
    udp_header_t h;
    h.src_port = utils::consume<port_addr_t>(ptr);
    h.dst_port = utils::consume<port_addr_t>(ptr);
    h.length = utils::consume<uint16_t>(ptr);
    h.checksum = utils::consume<uint16_t>(ptr);
    return h;
}

std::ostream& operator<<(std::ostream& out, const udp_header_t& h) {
    out << "[UDP] src_port:" << h.src_port << " dst_port:" << h.dst_port
        << " len:" << h.length << " checksum:0x" << std::hex << h.checksum;
    return out;
}

}  // namespace netforge