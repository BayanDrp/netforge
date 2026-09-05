#include "netforge/layers/icmp.hpp"

#include <cstring>
#include <vector>

#include "netforge/buffer/utils.hpp"

namespace netforge {

void icmp_header_t::produce(buffer& buf) const {
    buf.produce<uint8_t>(type);
    buf.produce<uint8_t>(code);
    buf.produce<uint16_t>(checksum);
    buf.produce<uint16_t>(identifier);
    buf.produce<uint16_t>(sequence);
}

icmp_header_t icmp_header_t::consume(buffer& buf) {
    icmp_header_t h;
    h.type = buf.consume<uint8_t>();
    h.code = buf.consume<uint8_t>();
    h.checksum = buf.consume<uint16_t>();
    h.identifier = buf.consume<uint16_t>();
    h.sequence = buf.consume<uint16_t>();
    return h;
}

void icmp_header_t::compute_checksum(const uint8_t* payload, int payload_len) {
    checksum = 0;
    std::vector<uint8_t> bytes(size() + payload_len);
    buffer buf(bytes.data(), bytes.size());
    produce(buf);
    if (payload && payload_len > 0)
        std::memcpy(bytes.data() + size(), payload, payload_len);
    checksum = utils::checksum(bytes.data(), bytes.size(), 0);
}

std::ostream& operator<<(std::ostream& out, const icmp_header_t& h) {
    out << "[ICMP] type:" << (int)h.type << " code:" << (int)h.code
        << " id:" << h.identifier << " seq:" << h.sequence
        << " checksum:0x" << std::hex << h.checksum;
    return out;
}

}  // namespace netforge