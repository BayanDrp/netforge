#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "netforge/buffer/buffer.hpp"

namespace netforge {

std::vector<uint8_t> encode_name(const std::string& name);
std::string decode_name(buffer& buf, uint8_t* msg_start);

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

    dns_header_t();

    void produce(buffer& buf);
    static dns_header_t consume(buffer& buf);

    friend std::ostream& operator<<(std::ostream& out, const dns_header_t& h);
};

struct dns_message_t {
    dns_header_t header;

    struct question_t {
        std::string qname;
        uint16_t qtype{1};
        uint16_t qclass{1};

        void produce(buffer& buf);
        static question_t consume(buffer& buf, uint8_t* msg_start);
    };

    struct answer_t {
        std::string name;
        uint16_t type;
        uint16_t rclass;
        uint32_t ttl;
        std::vector<uint8_t> rdata;

        void produce(buffer& buf);
        static answer_t consume(buffer& buf, uint8_t* msg_start);
    };

    std::vector<question_t> questions;
    std::vector<answer_t> answers;
    std::vector<answer_t> authorities;
    std::vector<answer_t> additional;

    void produce(buffer& buf);
    static dns_message_t consume(buffer& buf);

    friend std::ostream& operator<<(std::ostream& out, const dns_message_t& m);
};

}  // namespace netforge