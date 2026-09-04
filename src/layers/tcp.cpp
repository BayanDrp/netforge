#include "netforge/layers/tcp.hpp"

#include "netforge/buffer/utils.hpp"
#include <arpa/inet.h>
#include <cstring>

namespace netforge {

tcp_header_t::tcp_header_t() {
    src_port = 0;
    dst_port = 0;
    seq_no = 0;
    ack_no = 0;
    header_length = 5;
    NOP = 0;
    URG = 0;
    ACK = 0;
    PSH = 0;
    RST = 0;
    SYN = 0;
    FIN = 0;
    window_size = 0;
    checksum = 0;
    urgent_pointer = 0;
}

void tcp_header_t::produce(uint8_t*& ptr) {
    utils::produce<port_addr_t>(ptr, src_port);
    utils::produce<port_addr_t>(ptr, dst_port);
    utils::produce<uint32_t>(ptr, seq_no);
    utils::produce<uint32_t>(ptr, ack_no);
    utils::produce<uint16_t>(ptr,
        (header_length << 12) | (NOP << 6) | (URG << 5) | (ACK << 4) |
        (PSH << 3) | (RST << 2) | (SYN << 1) | FIN);
    utils::produce<uint16_t>(ptr, window_size);
    utils::produce<uint16_t>(ptr, checksum);
    utils::produce<uint16_t>(ptr, urgent_pointer);
}

tcp_header_t tcp_header_t::consume(uint8_t*& ptr) {
    tcp_header_t h;

    h.src_port = utils::consume<port_addr_t>(ptr);
    h.dst_port = utils::consume<port_addr_t>(ptr);
    h.seq_no = utils::consume<uint32_t>(ptr);
    h.ack_no = utils::consume<uint32_t>(ptr);

    uint16_t hl_flags = utils::consume<uint16_t>(ptr);
    h.header_length = hl_flags >> 12;
    h.NOP = (hl_flags >> 6) & 0x3F;
    h.URG = (hl_flags >> 5) & 0x1;
    h.ACK = (hl_flags >> 4) & 0x1;
    h.PSH = (hl_flags >> 3) & 0x1;
    h.RST = (hl_flags >> 2) & 0x1;
    h.SYN = (hl_flags >> 1) & 0x1;
    h.FIN = hl_flags & 0x1;

    h.window_size = utils::consume<uint16_t>(ptr);
    h.checksum = utils::consume<uint16_t>(ptr);
    h.urgent_pointer = utils::consume<uint16_t>(ptr);

    return h;
}

void tcp_header_t::compute_checksum(uint32_t src_ip, uint32_t dst_ip,
                                    const uint8_t* data, int data_len) {
    uint8_t pseudo[12];
    uint32_t nsrc = htonl(src_ip);
    uint32_t ndst = htonl(dst_ip);
    memcpy(pseudo, &nsrc, 4);
    memcpy(pseudo + 4, &ndst, 4);
    pseudo[8] = 0;
    pseudo[9] = 6;
    uint16_t nlen = htons((uint16_t)(size() + data_len));
    memcpy(pseudo + 10, &nlen, 2);

    uint32_t sum = utils::sum_every_16bits(pseudo, 12);

    uint8_t buf[20 + data_len];
    uint8_t* ptr = buf;
    checksum = 0;
    produce(ptr);
    if (data && data_len > 0)
        memcpy(buf + size(), data, data_len);

    checksum = utils::checksum(buf, size() + data_len, sum);
}

std::ostream& operator<<(std::ostream& out, const tcp_header_t& h) {
    out << "[TCP PACKET] ";
    out << h.src_port;
    out << " -> " << h.dst_port;
    out << " SEQ_NO:" << h.seq_no;
    out << " ACK_NO:" << h.ack_no;
    out << " [ ";
    if (h.ACK) out << "ACK ";
    if (h.SYN) out << "SYN ";
    if (h.PSH) out << "PSH ";
    if (h.RST) out << "RST ";
    if (h.FIN) out << "FIN ";
    out << "]";
    return out;
}

}  // namespace netforge