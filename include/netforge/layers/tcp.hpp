#pragma once

#include <cstdint>
#include <ostream>

namespace netforge {

struct tcp_header_t {
    using port_addr_t = uint16_t;

    port_addr_t src_port;
    port_addr_t dst_port;
    uint32_t seq_no;
    uint32_t ack_no;

    uint16_t FIN : 1;
    uint16_t SYN : 1;
    uint16_t RST : 1;
    uint16_t PSH : 1;
    uint16_t ACK : 1;
    uint16_t URG : 1;
    uint16_t NOP : 6;
    uint16_t header_length : 4;

    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    static constexpr size_t size() { return 20; }

    tcp_header_t();

    void produce(uint8_t*& ptr);
    static tcp_header_t consume(uint8_t*& ptr);
    void compute_checksum(uint32_t src_ip, uint32_t dst_ip,
                          const uint8_t* data, int data_len);

    friend std::ostream& operator<<(std::ostream& out, const tcp_header_t& h);
};

}  // namespace netforge