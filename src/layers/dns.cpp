#include "netforge/layers/dns.hpp"

#include <cstring>

namespace netforge {

std::vector<uint8_t> encode_name(const std::string& name) {
    std::vector<uint8_t> out;
    size_t start = 0;
    size_t end;
    while ((end = name.find('.', start)) != std::string::npos) {
        out.push_back(end - start);
        out.insert(out.end(), name.begin() + start, name.begin() + end);
        start = end + 1;
    }
    out.push_back(name.size() - start);
    out.insert(out.end(), name.begin() + start, name.end());
    out.push_back(0);
    return out;
}

std::string decode_name(buffer& buf, uint8_t* msg_start) {
    std::string name;
    while (true) {
        if (!buf.can_read(1)) break;
        uint8_t len = *buf.consume_bytes(1);
        if (len == 0) break;

        if ((len & 0xC0) == 0xC0) {
            if (!buf.can_read(1)) break;
            uint16_t offset = ((len & 0x3F) << 8) | *buf.consume_bytes(1);
            if (msg_start) {
                std::size_t restore = buf.position();
                buf.seek(offset);
                if (!name.empty()) name += '.';
                name += decode_name(buf, msg_start);
                buf.seek(restore);
            }
            break;
        }

        if (len > buf.remaining()) break;
        if (!name.empty()) name += '.';
        uint8_t* label = buf.consume_bytes(len);
        name.append(reinterpret_cast<char*>(label), len);
    }
    return name;
}

dns_header_t::dns_header_t() {
    id = qdcount = ancount = nscount = arcount = 0;
    rcode = z = ra = rd = tc = aa = opcode = qr = 0;
}

void dns_header_t::produce(buffer& buf) {
    buf.produce<uint16_t>(id);
    buf.produce<uint16_t>(
        (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) |
        (rd << 8) | (ra << 7) | (z << 4) | rcode);
    buf.produce<uint16_t>(qdcount);
    buf.produce<uint16_t>(ancount);
    buf.produce<uint16_t>(nscount);
    buf.produce<uint16_t>(arcount);
}

dns_header_t dns_header_t::consume(buffer& buf) {
    dns_header_t h;
    h.id = buf.consume<uint16_t>();
    uint16_t flags = buf.consume<uint16_t>();
    h.qr = (flags >> 15) & 1;
    h.opcode = (flags >> 11) & 0xF;
    h.aa = (flags >> 10) & 1;
    h.tc = (flags >> 9) & 1;
    h.rd = (flags >> 8) & 1;
    h.ra = (flags >> 7) & 1;
    h.z = (flags >> 4) & 0x7;
    h.rcode = flags & 0xF;
    h.qdcount = buf.consume<uint16_t>();
    h.ancount = buf.consume<uint16_t>();
    h.nscount = buf.consume<uint16_t>();
    h.arcount = buf.consume<uint16_t>();
    return h;
}

std::ostream& operator<<(std::ostream& out, const dns_header_t& h) {
    out << "[DNS] ID:0x" << std::hex << h.id << std::dec;
    out << " QR:" << h.qr << " OP:" << h.opcode;
    out << " AA:" << h.aa << " TC:" << h.tc << " RD:" << h.rd;
    out << " RA:" << h.ra << " Z:" << h.z << " RCODE:" << h.rcode;
    out << " QD:" << h.qdcount << " AN:" << h.ancount;
    out << " NS:" << h.nscount << " AR:" << h.arcount;
    return out;
}

void dns_message_t::question_t::produce(buffer& buf) {
    auto encoded = encode_name(qname);
    buf.produce_bytes(encoded.data(), encoded.size());
    buf.produce<uint16_t>(qtype);
    buf.produce<uint16_t>(qclass);
}

dns_message_t::question_t dns_message_t::question_t::consume(buffer& buf, uint8_t* msg_start) {
    question_t q;
    q.qname = decode_name(buf, msg_start);
    q.qtype = buf.consume<uint16_t>();
    q.qclass = buf.consume<uint16_t>();
    return q;
}

void dns_message_t::answer_t::produce(buffer& buf) {
    auto encoded = encode_name(name);
    buf.produce_bytes(encoded.data(), encoded.size());
    buf.produce<uint16_t>(type);
    buf.produce<uint16_t>(rclass);
    buf.produce<uint32_t>(ttl);
    buf.produce<uint16_t>(rdata.size());
    buf.produce_bytes(rdata.data(), rdata.size());
}

dns_message_t::answer_t dns_message_t::answer_t::consume(buffer& buf, uint8_t* msg_start) {
    answer_t a;
    a.name = decode_name(buf, msg_start);
    a.type = buf.consume<uint16_t>();
    a.rclass = buf.consume<uint16_t>();
    a.ttl = buf.consume<uint32_t>();
    uint16_t rdlen = buf.consume<uint16_t>();
    uint8_t* rdata = buf.consume_bytes(rdlen);
    a.rdata.assign(rdata, rdata + rdlen);
    return a;
}

void dns_message_t::produce(buffer& buf) {
    header.qdcount = questions.size();
    header.ancount = answers.size();
    header.nscount = authorities.size();
    header.arcount = additional.size();
    header.produce(buf);
    for (auto& q : questions) q.produce(buf);
    for (auto& a : answers) a.produce(buf);
    for (auto& a : authorities) a.produce(buf);
    for (auto& a : additional) a.produce(buf);
}

dns_message_t dns_message_t::consume(buffer& buf) {
    dns_message_t msg;
    uint8_t* msg_start = buf.data();
    msg.header = dns_header_t::consume(buf);
    for (uint16_t i = 0; i < msg.header.qdcount; i++)
        msg.questions.push_back(question_t::consume(buf, msg_start));
    for (uint16_t i = 0; i < msg.header.ancount; i++)
        msg.answers.push_back(answer_t::consume(buf, msg_start));
    for (uint16_t i = 0; i < msg.header.nscount; i++)
        msg.authorities.push_back(answer_t::consume(buf, msg_start));
    for (uint16_t i = 0; i < msg.header.arcount; i++)
        msg.additional.push_back(answer_t::consume(buf, msg_start));
    return msg;
}

std::ostream& operator<<(std::ostream& out, const dns_message_t& m) {
    out << m.header << "\n";
    for (auto& q : m.questions)
        out << "  Q: " << q.qname << " (type:" << q.qtype << " class:" << q.qclass << ")\n";
    for (auto& a : m.answers)
        out << "  A: " << a.name << " type:" << a.type << " ttl:" << a.ttl
            << " rdlen:" << a.rdata.size() << "\n";
    return out;
}

}  // namespace netforge