#pragma once
#include "netforge/buffer/utils.hpp"
#include <cstring>
namespace netforge {
struct udp_header_t {
        using port_addr_t = uint16_t;
        port_addr_t src_port;
        port_addr_t dst_port;
        uint16_t    length;
        uint16_t    checksum;

        static constexpr size_t size() { return 2 + 2 + 2 + 2; }

        udp_header_t() {
                src_port = 0;
                dst_port = 0;
                length   = 0;
                checksum = 0;
        }

        static udp_header_t consume(uint8_t*& ptr) {
                udp_header_t udp_header;
                udp_header.src_port = utils::consume<port_addr_t>(ptr);
                udp_header.dst_port = utils::consume<port_addr_t>(ptr);
                udp_header.length   = utils::consume<uint16_t>(ptr);
                udp_header.checksum = utils::consume<uint16_t>(ptr);
                return udp_header;
        }


        void produce(uint8_t*& ptr) const {
                utils::produce<port_addr_t>(ptr, src_port);
                utils::produce<port_addr_t>(ptr, dst_port);
                utils::produce<uint16_t>(ptr, length);
                utils::produce<uint16_t>(ptr, checksum);
        }
        
        friend std::ostream& operator<<(std::ostream& out, const udp_header_t& udp_header) {
                out << "src_port: " << udp_header.src_port << ", dst_port: " << udp_header.dst_port << ", length: " << udp_header.length
                    << ", checksum: " << udp_header.checksum;
                return out;
        }
};
}  // namespace netforge


