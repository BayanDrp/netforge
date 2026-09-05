#include "netforge/parser/dissect.hpp"

#include <arpa/inet.h>
#include <cstring>

#include "netforge/buffer/utils.hpp"
#include "netforge/parser/checksum.hpp"

namespace netforge {

bool dissect_frame(const uint8_t* data, std::size_t len, dissected_packet& out) {
    out = dissected_packet{};
    buffer buf(const_cast<uint8_t*>(data), len);

    try {
        out.ethernet = ethernet_header_t::consume(buf);
    } catch (const std::out_of_range&) {
        return false;
    }

    switch (out.ethernet.ethertype) {
        case 0x0800: {
            if (len < 34) return false;
            try {
                out.ipv4 = ipv4_header_t::consume(buf);
            } catch (const std::out_of_range&) {
                return false;
            }
            out.l3 = dissected_packet::l3_type::ipv4;
            out.ipv4_checksum_ok = checksum::verify(data + 14, 20);
            break;
        }
        case 0x86DD: {
            if (len < 54) return false;
            try {
                out.ipv6 = ipv6_header_t::consume(buf);
            } catch (const std::out_of_range&) {
                return false;
            }
            out.l3 = dissected_packet::l3_type::ipv6;
            break;
        }
        default:
            return false;
    }

    const uint16_t l4_proto = (out.l3 == dissected_packet::l3_type::ipv4) ? out.ipv4.protocol
                                                                          : out.ipv6.next_header;

    switch (l4_proto) {
        case 17: {
            try {
                out.udp = udp_header_t::consume(buf);
            } catch (const std::out_of_range&) {
                return false;
            }
            out.l4 = dissected_packet::l4_type::udp;
            if (out.udp.checksum != 0 && out.l3 == dissected_packet::l3_type::ipv4) {
                uint8_t pseudo[12];
                uint32_t nsrc = htonl(out.ipv4.source_ip);
                uint32_t ndst = htonl(out.ipv4.destination_ip);
                std::memcpy(pseudo, &nsrc, 4);
                std::memcpy(pseudo + 4, &ndst, 4);
                pseudo[8] = 0;
                pseudo[9] = 17;
                uint16_t nlen = htons(out.udp.length);
                std::memcpy(pseudo + 10, &nlen, 2);
                uint32_t sum = utils::sum_every_16bits(pseudo, 12);
                const std::size_t seg = len - 34 < out.udp.length ? len - 34 : out.udp.length;
                out.udp_checksum_ok = checksum::verify(data + 34, seg, sum);
            }
            out.payload = data + 42;
            out.payload_len = len > 42 ? len - 42 : 0;
            return true;
        }
        case 6: {
            try {
                out.tcp = tcp_header_t::consume(buf);
            } catch (const std::out_of_range&) {
                return false;
            }
            out.l4 = dissected_packet::l4_type::tcp;
            if (out.l3 == dissected_packet::l3_type::ipv4) {
                uint8_t pseudo[12];
                uint32_t nsrc = htonl(out.ipv4.source_ip);
                uint32_t ndst = htonl(out.ipv4.destination_ip);
                std::memcpy(pseudo, &nsrc, 4);
                std::memcpy(pseudo + 4, &ndst, 4);
                pseudo[8] = 0;
                pseudo[9] = 6;
                uint16_t nlen = htons(static_cast<uint16_t>(len - 34));
                std::memcpy(pseudo + 10, &nlen, 2);
                uint32_t sum = utils::sum_every_16bits(pseudo, 12);
                out.tcp_checksum_ok = checksum::verify(data + 34, len - 34, sum);
            }
            out.payload = data + 54;
            out.payload_len = len > 54 ? len - 54 : 0;
            return true;
        }
        case 1: {
            try {
                out.icmp = icmp_header_t::consume(buf);
            } catch (const std::out_of_range&) {
                return false;
            }
            out.l4 = dissected_packet::l4_type::icmp;
            out.payload = buf.data() + buf.position();
            out.payload_len = len - buf.position();
            return true;
        }
        case 58: {
            try {
                out.icmp = icmp_header_t::consume(buf);
            } catch (const std::out_of_range&) {
                return false;
            }
            out.l4 = dissected_packet::l4_type::icmpv6;
            out.payload = buf.data() + buf.position();
            out.payload_len = len - buf.position();
            return true;
        }
        default:
            out.payload = buf.data() + buf.position();
            out.payload_len = len - buf.position();
            return true;
    }
}

}  // namespace netforge