#include "netforge/layers/ipv4.hpp"

#include <arpa/inet.h>

#include "netforge/buffer/utils.hpp"

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

void ipv4_header_t::produce(buffer& buf) {
    buf.produce<uint8_t>((version << 4) | (ihl & 0x0F));
    buf.produce<uint8_t>((dscp << 2) | (ecn & 0x03));
    buf.produce<uint16_t>(total_length);
    buf.produce<uint16_t>(identification);
    buf.produce<uint16_t>((flags << 13) | (fragment_offset & 0x1FFF));
    buf.produce<uint8_t>(ttl);
    buf.produce<uint8_t>(protocol);
    buf.produce<uint16_t>(header_checksum);
    buf.produce<uint32_t>(source_ip);
    buf.produce<uint32_t>(destination_ip);
}

ipv4_header_t ipv4_header_t::consume(buffer& buf) {
    ipv4_header_t hdr;

    uint8_t version_ihl = buf.consume<uint8_t>();
    hdr.version = version_ihl >> 4;
    hdr.ihl = version_ihl & 0x0F;

    uint8_t tos = buf.consume<uint8_t>();
    hdr.dscp = tos >> 2;
    hdr.ecn = tos & 0x03;

    hdr.total_length = buf.consume<uint16_t>();
    hdr.identification = buf.consume<uint16_t>();

    uint16_t flags_frag = buf.consume<uint16_t>();
    hdr.flags = flags_frag >> 13;
    hdr.fragment_offset = flags_frag & 0x1FFF;

    hdr.ttl = buf.consume<uint8_t>();
    hdr.protocol = buf.consume<uint8_t>();
    hdr.header_checksum = buf.consume<uint16_t>();
    hdr.source_ip = buf.consume<uint32_t>();
    hdr.destination_ip = buf.consume<uint32_t>();

    return hdr;
}

void ipv4_header_t::compute_checksum() {
    header_checksum = 0;
    uint8_t bytes[20];
    buffer buf(bytes, sizeof(bytes));
    produce(buf);
    header_checksum = utils::checksum(bytes, 20, 0);
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