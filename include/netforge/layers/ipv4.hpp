#pragma once

#include <cstdint>
#include <ostream>

namespace netforge {

using ip_addr_t = uint32_t;

struct ipv4_header_t {
    uint8_t version : 4;
    uint8_t ihl : 4;

    uint8_t dscp : 6;
    uint8_t ecn : 2;

    uint16_t total_length;
    uint16_t identification;

    uint16_t flags : 3;
    uint16_t fragment_offset : 13;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    ip_addr_t source_ip;
    ip_addr_t destination_ip;

    static constexpr size_t size() { return 20; }

    ipv4_header_t();

    void produce(uint8_t*& ptr);
    static ipv4_header_t consume(uint8_t*& ptr);
    void compute_checksum();

    friend std::ostream& operator<<(std::ostream& out, ipv4_header_t& h);
};

}  // namespace netforge