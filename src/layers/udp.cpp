#include "netforge/layers/udp.hpp"

namespace netforge {

udp_header_t::udp_header_t() {
    src_port = 0;
    dst_port = 0;
    length = 0;
    checksum = 0;
}

void udp_header_t::produce(buffer& buf) const {
    buf.produce<port_addr_t>(src_port);
    buf.produce<port_addr_t>(dst_port);
    buf.produce<uint16_t>(length);
    buf.produce<uint16_t>(checksum);
}

udp_header_t udp_header_t::consume(buffer& buf) {
    udp_header_t h;
    h.src_port = buf.consume<port_addr_t>();
    h.dst_port = buf.consume<port_addr_t>();
    h.length = buf.consume<uint16_t>();
    h.checksum = buf.consume<uint16_t>();
    return h;
}

std::ostream& operator<<(std::ostream& out, const udp_header_t& h) {
    out << "[UDP] src_port:" << h.src_port << " dst_port:" << h.dst_port
        << " len:" << h.length << " checksum:0x" << std::hex << h.checksum;
    return out;
}

}  // namespace netforge