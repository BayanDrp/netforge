#ifndef NETFORGE_PARSER_DISSECT_HPP
#define NETFORGE_PARSER_DISSECT_HPP

#include <cstddef>
#include <cstdint>

#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/icmp.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/ipv6.hpp"
#include "netforge/layers/tcp.hpp"
#include "netforge/layers/udp.hpp"

namespace netforge {

struct dissected_packet {
    ethernet_header_t ethernet;
    ipv4_header_t ipv4;
    ipv6_header_t ipv6;
    udp_header_t udp;
    tcp_header_t tcp;
    icmp_header_t icmp;

    enum class l3_type { none, ipv4, ipv6 } l3 = l3_type::none;
    enum class l4_type { none, udp, tcp, icmp, icmpv6 } l4 = l4_type::none;

    const uint8_t* payload = nullptr;
    std::size_t payload_len = 0;

    bool ipv4_checksum_ok = false;
    bool tcp_checksum_ok = false;
    bool udp_checksum_ok = false;
};

bool dissect_frame(const uint8_t* data, std::size_t len, dissected_packet& out);

}  // namespace netforge

#endif  // NETFORGE_PARSER_DISSECT_HPP