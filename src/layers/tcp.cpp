#include "netforge/layers/tcp.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <vector>

#include "netforge/buffer/utils.hpp"

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

void tcp_header_t::produce(buffer& buf) {
    buf.produce<port_addr_t>(src_port);
    buf.produce<port_addr_t>(dst_port);
    buf.produce<uint32_t>(seq_no);
    buf.produce<uint32_t>(ack_no);
    buf.produce<uint16_t>(
        (header_length << 12) | (NOP << 6) | (URG << 5) | (ACK << 4) |
        (PSH << 3) | (RST << 2) | (SYN << 1) | FIN);
    buf.produce<uint16_t>(window_size);
    buf.produce<uint16_t>(checksum);
    buf.produce<uint16_t>(urgent_pointer);
}

tcp_header_t tcp_header_t::consume(buffer& buf) {
    tcp_header_t h;

    h.src_port = buf.consume<port_addr_t>();
    h.dst_port = buf.consume<port_addr_t>();
    h.seq_no = buf.consume<uint32_t>();
    h.ack_no = buf.consume<uint32_t>();

    uint16_t hl_flags = buf.consume<uint16_t>();
    h.header_length = hl_flags >> 12;
    h.NOP = (hl_flags >> 6) & 0x3F;
    h.URG = (hl_flags >> 5) & 0x1;
    h.ACK = (hl_flags >> 4) & 0x1;
    h.PSH = (hl_flags >> 3) & 0x1;
    h.RST = (hl_flags >> 2) & 0x1;
    h.SYN = (hl_flags >> 1) & 0x1;
    h.FIN = hl_flags & 0x1;

    h.window_size = buf.consume<uint16_t>();
    h.checksum = buf.consume<uint16_t>();
    h.urgent_pointer = buf.consume<uint16_t>();

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

    std::vector<uint8_t> bytes(size() + data_len);
    buffer buf(bytes.data(), bytes.size());
    checksum = 0;
    produce(buf);
    if (data && data_len > 0)
        memcpy(bytes.data() + size(), data, data_len);

    checksum = utils::checksum(bytes.data(), bytes.size(), sum);
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