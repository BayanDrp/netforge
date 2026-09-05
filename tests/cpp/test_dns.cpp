#include <cstdint>
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/layers/dns.hpp"

#include "test_util.hpp"

using namespace netforge;

int main() {
    auto enc = encode_name("example.com");
    CHECK(enc.size() == 13);
    CHECK(enc[0] == 7);
    CHECK(enc[1] == 'e');
    CHECK(enc[8] == 3);
    CHECK(enc[9] == 'c');
    CHECK(enc[12] == 0);

    auto enc2 = encode_name("www.google.com");
    CHECK(enc2.size() == 16);
    CHECK(enc2[0] == 3 && enc2[1] == 'w');

    std::vector<uint8_t> nm = enc;
    buffer nb(nm.data(), nm.size());
    CHECK(decode_name(nb, nm.data()) == "example.com");

    dns_header_t h;
    h.id = 0x1337;
    h.qr = 1;
    h.opcode = 2;
    h.aa = 1;
    h.tc = 0;
    h.rd = 1;
    h.ra = 0;
    h.z = 3;
    h.rcode = 4;
    h.qdcount = 1;
    h.ancount = 2;
    h.nscount = 3;
    h.arcount = 4;

    uint8_t hw[12];
    buffer ho(hw, sizeof(hw));
    h.produce(ho);
    buffer hi(hw, sizeof(hw));
    dns_header_t bh = dns_header_t::consume(hi);
    CHECK(bh.id == 0x1337);
    CHECK(bh.qr == 1);
    CHECK(bh.opcode == 2);
    CHECK(bh.aa == 1);
    CHECK(bh.tc == 0);
    CHECK(bh.rd == 1);
    CHECK(bh.ra == 0);
    CHECK(bh.z == 3);
    CHECK(bh.rcode == 4);
    CHECK(bh.qdcount == 1 && bh.ancount == 2 && bh.nscount == 3 && bh.arcount == 4);

    dns_message_t m;
    dns_message_t::question_t q;
    q.qname = "example.com";
    q.qtype = 1;
    q.qclass = 1;
    m.questions.push_back(q);
    dns_message_t::answer_t a;
    a.name = "example.com";
    a.type = 1;
    a.rclass = 1;
    a.ttl = 300;
    a.rdata = {127, 0, 0, 1};
    m.answers.push_back(a);

    std::vector<uint8_t> msgbuf(512);
    buffer mb(msgbuf.data(), msgbuf.size());
    m.produce(mb);
    CHECK(mb.position() == 56);

    buffer mi(msgbuf.data(), mb.position());
    dns_message_t back = dns_message_t::consume(mi);
    CHECK(back.header.qdcount == 1);
    CHECK(back.header.ancount == 1);
    CHECK(back.questions.size() == 1);
    CHECK(back.questions[0].qname == "example.com");
    CHECK(back.questions[0].qtype == 1);
    CHECK(back.answers.size() == 1);
    CHECK(back.answers[0].name == "example.com");
    CHECK(back.answers[0].type == 1);
    CHECK(back.answers[0].ttl == 300);
    CHECK(back.answers[0].rdata.size() == 4);
    CHECK(back.answers[0].rdata[0] == 127 && back.answers[0].rdata[3] == 1);
    CHECK(mi.position() == 56);

    uint8_t compressed[45] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e', 0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
        0x7f, 0x00, 0x00, 0x01};
    buffer ci(compressed, sizeof(compressed));
    dns_message_t cmsg = dns_message_t::consume(ci);
    CHECK(cmsg.header.qdcount == 1);
    CHECK(cmsg.header.ancount == 1);
    CHECK(cmsg.questions[0].qname == "example.com");
    CHECK(cmsg.answers[0].name == "example.com");
    CHECK(cmsg.answers[0].rdata[3] == 1);

    DONE();
}