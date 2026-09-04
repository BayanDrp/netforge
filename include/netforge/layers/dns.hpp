#pragma once
#include "netforge/buffer/utils.hpp"
#include <cstdint>
#include <cstring>
#include <ostream>
#include <string>
#include <vector>

namespace netforge {

inline std::vector<uint8_t> encode_name(const std::string& name) {
    std::vector<uint8_t> out;
    size_t start = 0, end;
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

inline std::string decode_name(uint8_t*& ptr, uint8_t* msg_start = nullptr) {
    std::string name;
    while (true) {
        uint8_t len = *ptr++;
        if (len == 0) break;

        if ((len & 0xC0) == 0xC0) {
            uint16_t offset = ((len & 0x3F) << 8) | *ptr++;
            if (msg_start) {
                uint8_t* saved = ptr;
                ptr = msg_start + offset;
                if (!name.empty()) name += '.';
                name += decode_name(ptr, msg_start);
                ptr = saved;
            }
            break;
        }

        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<char*>(ptr), len);
        ptr += len;
    }
    return name;
}

struct dns_header_t {
    uint16_t id;

    uint16_t rcode : 4;
    uint16_t z : 3;
    uint16_t ra : 1;
    uint16_t rd : 1;
    uint16_t tc : 1;
    uint16_t aa : 1;
    uint16_t opcode : 4;
    uint16_t qr : 1;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    static constexpr size_t size() { return 12; }

    dns_header_t() {
        id = qdcount = ancount = nscount = arcount = 0;
        rcode = z = ra = rd = tc = aa = opcode = qr = 0;
    }

    static dns_header_t consume(uint8_t*& ptr) {
        dns_header_t hdr;
        hdr.id = utils::consume<uint16_t>(ptr);
        uint16_t flags = utils::consume<uint16_t>(ptr);
        hdr.qr     = (flags >> 15) & 1;
        hdr.opcode = (flags >> 11) & 0xF;
        hdr.aa     = (flags >> 10) & 1;
        hdr.tc     = (flags >> 9) & 1;
        hdr.rd     = (flags >> 8) & 1;
        hdr.ra     = (flags >> 7) & 1;
        hdr.z      = (flags >> 4) & 0x7;
        hdr.rcode  = flags & 0xF;
        hdr.qdcount = utils::consume<uint16_t>(ptr);
        hdr.ancount = utils::consume<uint16_t>(ptr);
        hdr.nscount = utils::consume<uint16_t>(ptr);
        hdr.arcount = utils::consume<uint16_t>(ptr);
        return hdr;
    }

    void produce(uint8_t*& ptr) {
        utils::produce<uint16_t>(ptr, id);
        utils::produce<uint16_t>(ptr,
            (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) |
            (rd << 8) | (ra << 7) | (z << 4) | rcode);
        utils::produce<uint16_t>(ptr, qdcount);
        utils::produce<uint16_t>(ptr, ancount);
        utils::produce<uint16_t>(ptr, nscount);
        utils::produce<uint16_t>(ptr, arcount);
    }

    friend std::ostream& operator<<(std::ostream& out, const dns_header_t& h) {
        out << "[DNS] ID:0x" << std::hex << h.id << std::dec;
        out << " QR:" << h.qr << " OP:" << h.opcode;
        out << " AA:" << h.aa << " TC:" << h.tc << " RD:" << h.rd;
        out << " RA:" << h.ra << " Z:" << h.z << " RCODE:" << h.rcode;
        out << " QD:" << h.qdcount << " AN:" << h.ancount;
        out << " NS:" << h.nscount << " AR:" << h.arcount;
        return out;
    }
};

struct dns_message_t {
    dns_header_t header;

    struct question_t {
        std::string qname;
        uint16_t qtype{1};
        uint16_t qclass{1};

        void produce(uint8_t*& ptr) {
            auto encoded = encode_name(qname);
            memcpy(ptr, encoded.data(), encoded.size());
            ptr += encoded.size();
            utils::produce<uint16_t>(ptr, qtype);
            utils::produce<uint16_t>(ptr, qclass);
        }

        static question_t consume(uint8_t*& ptr, uint8_t* msg_start = nullptr) {
            question_t q;
            q.qname  = decode_name(ptr, msg_start);
            q.qtype  = utils::consume<uint16_t>(ptr);
            q.qclass = utils::consume<uint16_t>(ptr);
            return q;
        }
    };

    struct answer_t {
        std::string name;
        uint16_t type;
        uint16_t rclass;
        uint32_t ttl;
        std::vector<uint8_t> rdata;

        void produce(uint8_t*& ptr) {
            auto encoded = encode_name(name);
            memcpy(ptr, encoded.data(), encoded.size());
            ptr += encoded.size();
            utils::produce<uint16_t>(ptr, type);
            utils::produce<uint16_t>(ptr, rclass);
            utils::produce<uint32_t>(ptr, ttl);
            utils::produce<uint16_t>(ptr, rdata.size());
            memcpy(ptr, rdata.data(), rdata.size());
            ptr += rdata.size();
        }

        static answer_t consume(uint8_t*& ptr, uint8_t* msg_start = nullptr) {
            answer_t a;
            a.name   = decode_name(ptr, msg_start);
            a.type   = utils::consume<uint16_t>(ptr);
            a.rclass = utils::consume<uint16_t>(ptr);
            a.ttl    = utils::consume<uint32_t>(ptr);
            uint16_t rdlen = utils::consume<uint16_t>(ptr);
            a.rdata.assign(ptr, ptr + rdlen);
            ptr += rdlen;
            return a;
        }
    };

    std::vector<question_t> questions;
    std::vector<answer_t> answers;
    std::vector<answer_t> authorities;
    std::vector<answer_t> additional;

    void produce(uint8_t*& ptr) {
        header.qdcount = questions.size();
        header.ancount = answers.size();
        header.nscount = authorities.size();
        header.arcount = additional.size();
        header.produce(ptr);
        for (auto& q : questions)   q.produce(ptr);
        for (auto& a : answers)     a.produce(ptr);
        for (auto& a : authorities) a.produce(ptr);
        for (auto& a : additional)  a.produce(ptr);
    }

    static dns_message_t consume(uint8_t*& ptr) {
        dns_message_t msg;
        uint8_t* msg_start = ptr;
        msg.header = dns_header_t::consume(ptr);
        for (uint16_t i = 0; i < msg.header.qdcount; i++)
            msg.questions.push_back(question_t::consume(ptr, msg_start));
        for (uint16_t i = 0; i < msg.header.ancount; i++)
            msg.answers.push_back(answer_t::consume(ptr, msg_start));
        for (uint16_t i = 0; i < msg.header.nscount; i++)
            msg.authorities.push_back(answer_t::consume(ptr, msg_start));
        for (uint16_t i = 0; i < msg.header.arcount; i++)
            msg.additional.push_back(answer_t::consume(ptr, msg_start));
        return msg;
    }

    friend std::ostream& operator<<(std::ostream& out, const dns_message_t& m) {
        out << m.header << "\n";
        for (auto& q : m.questions)
            out << "  Q: " << q.qname << " (type:" << q.qtype << " class:" << q.qclass << ")\n";
        for (auto& a : m.answers)
            out << "  A: " << a.name << " type:" << a.type << " ttl:" << a.ttl
                << " rdlen:" << a.rdata.size() << "\n";
        return out;
    }
};

}  // namespace netforge
