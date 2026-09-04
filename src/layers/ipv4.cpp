#include "netforge/layers/ipv4.hpp"

#include "netforge/buffer/utils.hpp"
#include <arpa/inet.h>

namespace netforge {

ipv4_header_t::ipv4_header_t() {
    version = 4;
    ihl = 5;
    dscp = 0;
    ecn = 0;
    total_length = 0;
    identification = 0;
    flags = 0;
    fragment_offset = 0;
    ttl = 64;
    protocol = 0;
    header_checksum = 0;
    source_ip = 0;
    destination_ip = 0;
}

void ipv4_header_t::produce(uint8_t*& ptr) {
    utils::produce<uint8_t>(ptr, (version << 4) | (ihl & 0x0F));
    utils::produce<uint8_t>(ptr, (dscp << 2) | (ecn & 0x03));
    utils::produce<uint16_t>(ptr, total_length);
    utils::produce<uint16_t>(ptr, identification);
    utils::produce<uint16_t>(ptr, (flags << 13) | (fragment_offset & 0x1FFF));
    utils::produce<uint8_t>(ptr, ttl);
    utils::produce<uint8_t>(ptr, protocol);
    utils::produce<uint16_t>(ptr, header_checksum);
    utils::produce<uint32_t>(ptr, source_ip);
    utils::produce<uint32_t>(ptr, destination_ip);
}

ipv4_header_t ipv4_header_t::consume(uint8_t*& ptr) {
    ipv4_header_t hdr;

    uint8_t version_ihl = utils::consume<uint8_t>(ptr);
    hdr.version = version_ihl >> 4;
    hdr.ihl = version_ihl & 0x0F;

    uint8_t tos = utils::consume<uint8_t>(ptr);
    hdr.dscp = tos >> 2;
    hdr.ecn = tos & 0x03;

    hdr.total_length = utils::consume<uint16_t>(ptr);
    hdr.identification = utils::consume<uint16_t>(ptr);

    uint16_t flags_frag = utils::consume<uint16_t>(ptr);
    hdr.flags = flags_frag >> 13;
    hdr.fragment_offset = flags_frag & 0x1FFF;

    hdr.ttl = utils::consume<uint8_t>(ptr);
    hdr.protocol = utils::consume<uint8_t>(ptr);
    hdr.header_checksum = utils::consume<uint16_t>(ptr);
    hdr.source_ip = utils::consume<uint32_t>(ptr);
    hdr.destination_ip = utils::consume<uint32_t>(ptr);

    return hdr;
}

void ipv4_header_t::compute_checksum() {
    header_checksum = 0;
    uint8_t buf[20];
    uint8_t* ptr = buf;
    produce(ptr);
    header_checksum = utils::checksum(buf, 20, 0);
}

std::ostream& operator<<(std::ostream& out, ipv4_header_t& h) {
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    struct in_addr sa, da;
    sa.s_addr = htonl(h.source_ip);
    da.s_addr = htonl(h.destination_ip);
    inet_ntop(AF_INET, &sa, src, sizeof(src));
    inet_ntop(AF_INET, &da, dst, sizeof(dst));

    out << "[IPv4] ";
    out << src << " -> " << dst;
    out << " PROTO:" << (int)h.protocol;
    out << " TTL:" << (int)h.ttl;
    out << " LEN:" << h.total_length;
    out << " ID:0x" << std::hex << h.identification << std::dec;
    out << " CHK:0x" << std::hex << h.header_checksum << std::dec;
    return out;
}

}  // namespace netforge