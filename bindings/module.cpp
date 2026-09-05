#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "netforge/buffer/buffer.hpp"
#include "netforge/io/raw_socket.hpp"
#include "netforge/io/sniffer.hpp"
#include "netforge/layers/dns.hpp"
#include "netforge/layers/ethernet.hpp"
#include "netforge/layers/icmp.hpp"
#include "netforge/layers/ipv4.hpp"
#include "netforge/layers/ipv6.hpp"
#include "netforge/layers/tcp.hpp"
#include "netforge/layers/udp.hpp"
#include "netforge/packet/mac.hpp"
#include "netforge/packet/packet.hpp"

namespace py = pybind11;

namespace netforge {
namespace bindings {

template <typename T>
py::bytes to_bytes(T layer) {
    std::vector<uint8_t> wire(1500);
    buffer buf(wire.data(), wire.size());
    layer.produce(buf);
    return py::bytes(std::string(reinterpret_cast<const char*>(wire.data()), buf.position()));
}

template <typename T>
T from_bytes(const std::string& wire) {
    buffer buf(reinterpret_cast<uint8_t*>(const_cast<char*>(wire.data())), wire.size());
    return T::consume(buf);
}

uint32_t ipv4_from_string(const std::string& s) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 ||
        c > 255 || d > 255)
        throw std::runtime_error("ipv4_from_string: invalid address: " + s);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string ipv4_to_string(uint32_t v) {
    return std::to_string((v >> 24) & 0xFF) + "." + std::to_string((v >> 16) & 0xFF) + "." +
           std::to_string((v >> 8) & 0xFF) + "." + std::to_string(v & 0xFF);
}

py::bytes make_dns_query(const std::string& hostname, uint16_t id, uint16_t src_port) {
    dns_message_t dns;
    dns.header.id = id;
    dns.header.rd = 1;
    dns_message_t::question_t q;
    q.qname = hostname;
    q.qtype = 1;
    q.qclass = 1;
    dns.questions.push_back(q);

    std::vector<uint8_t> dns_wire(512);
    buffer dns_buf(dns_wire.data(), dns_wire.size());
    dns.produce(dns_buf);
    uint16_t udp_len = static_cast<uint16_t>(8 + dns_buf.position());

    udp_header_t udp;
    udp.src_port = src_port;
    udp.dst_port = 53;
    udp.length = udp_len;
    udp.checksum = 0;

    ipv4_header_t ip;
    ip.protocol = 17;
    ip.ttl = 64;
    ip.source_ip = ipv4_from_string("127.0.0.1");
    ip.destination_ip = ipv4_from_string("127.0.0.1");
    ip.total_length = static_cast<uint16_t>(20 + udp_len);
    ip.compute_checksum();

    ethernet_header_t eth;
    std::memset(eth.dst_mac, 0, 6);
    std::memset(eth.src_mac, 0, 6);
    eth.ethertype = 0x0800;

    packet pkt;
    pkt.add(eth);
    pkt.add(ip);
    pkt.add(udp);
    pkt.add(dns);

    return py::bytes(
        std::string(reinterpret_cast<const char*>(pkt.data()), pkt.size()));
}

}  // namespace bindings
}  // namespace netforge

PYBIND11_MODULE(_netforge, m) {
    m.doc() = "netforge: C++17 packet crafting/sniffing library (Python bindings)";

    using namespace netforge;
    using namespace netforge::bindings;

    py::class_<mac_t>(m, "Mac")
        .def(py::init<>())
        .def(py::init<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>())
        .def_property(
            "addr",
            [](const mac_t& mac) {
                return py::bytes(std::string(reinterpret_cast<const char*>(mac.addr), 6));
            },
            [](mac_t& mac, const std::string& v) {
                if (v.size() != 6) throw std::runtime_error("Mac.addr expects exactly 6 bytes");
                std::memcpy(mac.addr, v.data(), 6);
            })
        .def("to_string", &mac_t::to_string)
        .def_static("from_string", &mac_t::from_string)
        .def_static("broadcast", &mac_t::broadcast)
        .def_static("zero", &mac_t::zero)
        .def("__eq__", [](const mac_t& a, const mac_t& b) { return a == b; })
        .def("__str__", [](const mac_t& mac) { return mac.to_string(); });

    py::class_<ethernet_header_t>(m, "EthernetHeader")
        .def(py::init<>())
        .def_property(
            "dst_mac",
            [](const ethernet_header_t& h) {
                return py::bytes(std::string(reinterpret_cast<const char*>(h.dst_mac), 6));
            },
            [](ethernet_header_t& h, const std::string& v) {
                if (v.size() != 6) throw std::runtime_error("dst_mac expects exactly 6 bytes");
                std::memcpy(h.dst_mac, v.data(), 6);
            })
        .def_property(
            "src_mac",
            [](const ethernet_header_t& h) {
                return py::bytes(std::string(reinterpret_cast<const char*>(h.src_mac), 6));
            },
            [](ethernet_header_t& h, const std::string& v) {
                if (v.size() != 6) throw std::runtime_error("src_mac expects exactly 6 bytes");
                std::memcpy(h.src_mac, v.data(), 6);
            })
        .def_readwrite("ethertype", &ethernet_header_t::ethertype)
        .def("to_bytes", &to_bytes<ethernet_header_t>)
        .def_static("from_bytes", &from_bytes<ethernet_header_t>)
        .def("__str__", [](const ethernet_header_t& h) {
            std::ostringstream ss;
            ss << h;
            return ss.str();
        });

    py::class_<ipv4_header_t>(m, "Ipv4Header")
        .def(py::init<>())
        .def_property("version", [](const ipv4_header_t& h) { return h.version; },
                      [](ipv4_header_t& h, uint8_t v) { h.version = v; })
        .def_property("ihl", [](const ipv4_header_t& h) { return h.ihl; },
                      [](ipv4_header_t& h, uint8_t v) { h.ihl = v; })
        .def_property("dscp", [](const ipv4_header_t& h) { return h.dscp; },
                      [](ipv4_header_t& h, uint8_t v) { h.dscp = v; })
        .def_property("ecn", [](const ipv4_header_t& h) { return h.ecn; },
                      [](ipv4_header_t& h, uint8_t v) { h.ecn = v; })
        .def_readwrite("total_length", &ipv4_header_t::total_length)
        .def_readwrite("identification", &ipv4_header_t::identification)
        .def_property("flags", [](const ipv4_header_t& h) { return h.flags; },
                      [](ipv4_header_t& h, uint16_t v) { h.flags = v; })
        .def_property("fragment_offset",
                      [](const ipv4_header_t& h) { return h.fragment_offset; },
                      [](ipv4_header_t& h, uint16_t v) { h.fragment_offset = v; })
        .def_readwrite("ttl", &ipv4_header_t::ttl)
        .def_readwrite("protocol", &ipv4_header_t::protocol)
        .def_readwrite("header_checksum", &ipv4_header_t::header_checksum)
        .def_readwrite("source_ip", &ipv4_header_t::source_ip)
        .def_readwrite("destination_ip", &ipv4_header_t::destination_ip)
        .def("compute_checksum", &ipv4_header_t::compute_checksum)
        .def("to_bytes", &to_bytes<ipv4_header_t>)
        .def_static("from_bytes", &from_bytes<ipv4_header_t>)
        .def("__str__", [](ipv4_header_t& h) {
            std::ostringstream ss;
            ss << h;
            return ss.str();
        });

    py::class_<ipv6_header_t>(m, "Ipv6Header")
        .def(py::init<>())
        .def_readwrite("version", &ipv6_header_t::version)
        .def_readwrite("traffic_class", &ipv6_header_t::traffic_class)
        .def_readwrite("flow_label", &ipv6_header_t::flow_label)
        .def_readwrite("payload_length", &ipv6_header_t::payload_length)
        .def_readwrite("next_header", &ipv6_header_t::next_header)
        .def_readwrite("hop_limit", &ipv6_header_t::hop_limit)
        .def_property(
            "source",
            [](const ipv6_header_t& h) {
                return py::bytes(std::string(reinterpret_cast<const char*>(h.source_addr), 16));
            },
            [](ipv6_header_t& h, const std::string& v) {
                if (v.size() != 16) throw std::runtime_error("Ipv6Header.source expects 16 bytes");
                std::memcpy(h.source_addr, v.data(), 16);
            })
        .def_property(
            "destination",
            [](const ipv6_header_t& h) {
                return py::bytes(
                    std::string(reinterpret_cast<const char*>(h.destination_addr), 16));
            },
            [](ipv6_header_t& h, const std::string& v) {
                if (v.size() != 16)
                    throw std::runtime_error("Ipv6Header.destination expects 16 bytes");
                std::memcpy(h.destination_addr, v.data(), 16);
            })
        .def("to_bytes", &to_bytes<ipv6_header_t>)
        .def_static("from_bytes", &from_bytes<ipv6_header_t>)
        .def("__str__", [](const ipv6_header_t& h) {
            std::ostringstream ss;
            ss << h;
            return ss.str();
        });

    py::class_<udp_header_t>(m, "UdpHeader")
        .def(py::init<>())
        .def_readwrite("src_port", &udp_header_t::src_port)
        .def_readwrite("dst_port", &udp_header_t::dst_port)
        .def_readwrite("length", &udp_header_t::length)
        .def_readwrite("checksum", &udp_header_t::checksum)
        .def("to_bytes", &to_bytes<udp_header_t>)
        .def_static("from_bytes", &from_bytes<udp_header_t>)
        .def("__str__", [](const udp_header_t& h) {
            std::ostringstream ss;
            ss << h;
            return ss.str();
        });

    py::class_<tcp_header_t>(m, "TcpHeader")
        .def(py::init<>())
        .def_readwrite("src_port", &tcp_header_t::src_port)
        .def_readwrite("dst_port", &tcp_header_t::dst_port)
        .def_readwrite("seq_no", &tcp_header_t::seq_no)
        .def_readwrite("ack_no", &tcp_header_t::ack_no)
        .def_property("FIN", [](const tcp_header_t& h) { return h.FIN; },
                      [](tcp_header_t& h, uint16_t v) { h.FIN = v; })
        .def_property("SYN", [](const tcp_header_t& h) { return h.SYN; },
                      [](tcp_header_t& h, uint16_t v) { h.SYN = v; })
        .def_property("RST", [](const tcp_header_t& h) { return h.RST; },
                      [](tcp_header_t& h, uint16_t v) { h.RST = v; })
        .def_property("PSH", [](const tcp_header_t& h) { return h.PSH; },
                      [](tcp_header_t& h, uint16_t v) { h.PSH = v; })
        .def_property("ACK", [](const tcp_header_t& h) { return h.ACK; },
                      [](tcp_header_t& h, uint16_t v) { h.ACK = v; })
        .def_property("URG", [](const tcp_header_t& h) { return h.URG; },
                      [](tcp_header_t& h, uint16_t v) { h.URG = v; })
        .def_property("header_length",
                      [](const tcp_header_t& h) { return h.header_length; },
                      [](tcp_header_t& h, uint16_t v) { h.header_length = v; })
        .def_readwrite("window_size", &tcp_header_t::window_size)
        .def_readwrite("checksum", &tcp_header_t::checksum)
        .def_readwrite("urgent_pointer", &tcp_header_t::urgent_pointer)
        .def("compute_checksum",
             [](tcp_header_t& h, uint32_t src_ip, uint32_t dst_ip, const std::string& payload) {
                 h.compute_checksum(src_ip, dst_ip,
                                    reinterpret_cast<const uint8_t*>(payload.data()),
                                    static_cast<int>(payload.size()));
             })
        .def("to_bytes", &to_bytes<tcp_header_t>)
        .def_static("from_bytes", &from_bytes<tcp_header_t>)
        .def("__str__", [](const tcp_header_t& h) {
            std::ostringstream ss;
            ss << h;
            return ss.str();
        });

    py::class_<icmp_header_t>(m, "IcmpHeader")
        .def(py::init<>())
        .def_readwrite("type", &icmp_header_t::type)
        .def_readwrite("code", &icmp_header_t::code)
        .def_readwrite("checksum", &icmp_header_t::checksum)
        .def_readwrite("identifier", &icmp_header_t::identifier)
        .def_readwrite("sequence", &icmp_header_t::sequence)
        .def("compute_checksum",
             [](icmp_header_t& h, const std::string& payload) {
                 h.compute_checksum(reinterpret_cast<const uint8_t*>(payload.data()),
                                    static_cast<int>(payload.size()));
             })
        .def("to_bytes", &to_bytes<icmp_header_t>)
        .def_static("from_bytes", &from_bytes<icmp_header_t>)
        .def("__str__", [](const icmp_header_t& h) {
            std::ostringstream ss;
            ss << h;
            return ss.str();
        });

    py::class_<dns_header_t>(m, "DnsHeader")
        .def(py::init<>())
        .def_readwrite("id", &dns_header_t::id)
        .def_property("qr", [](const dns_header_t& h) { return h.qr; },
                      [](dns_header_t& h, uint16_t v) { h.qr = v; })
        .def_property("opcode", [](const dns_header_t& h) { return h.opcode; },
                      [](dns_header_t& h, uint16_t v) { h.opcode = v; })
        .def_property("aa", [](const dns_header_t& h) { return h.aa; },
                      [](dns_header_t& h, uint16_t v) { h.aa = v; })
        .def_property("tc", [](const dns_header_t& h) { return h.tc; },
                      [](dns_header_t& h, uint16_t v) { h.tc = v; })
        .def_property("rd", [](const dns_header_t& h) { return h.rd; },
                      [](dns_header_t& h, uint16_t v) { h.rd = v; })
        .def_property("ra", [](const dns_header_t& h) { return h.ra; },
                      [](dns_header_t& h, uint16_t v) { h.ra = v; })
        .def_property("z", [](const dns_header_t& h) { return h.z; },
                      [](dns_header_t& h, uint16_t v) { h.z = v; })
        .def_property("rcode", [](const dns_header_t& h) { return h.rcode; },
                      [](dns_header_t& h, uint16_t v) { h.rcode = v; })
        .def_readwrite("qdcount", &dns_header_t::qdcount)
        .def_readwrite("ancount", &dns_header_t::ancount)
        .def_readwrite("nscount", &dns_header_t::nscount)
        .def_readwrite("arcount", &dns_header_t::arcount)
        .def("__str__", [](const dns_header_t& h) {
            std::ostringstream ss;
            ss << h;
            return ss.str();
        });

    py::class_<dns_message_t::question_t>(m, "DnsQuestion")
        .def(py::init<>())
        .def_readwrite("qname", &dns_message_t::question_t::qname)
        .def_readwrite("qtype", &dns_message_t::question_t::qtype)
        .def_readwrite("qclass", &dns_message_t::question_t::qclass);

    py::class_<dns_message_t::answer_t>(m, "DnsAnswer")
        .def(py::init<>())
        .def_readwrite("name", &dns_message_t::answer_t::name)
        .def_readwrite("type", &dns_message_t::answer_t::type)
        .def_readwrite("rclass", &dns_message_t::answer_t::rclass)
        .def_readwrite("ttl", &dns_message_t::answer_t::ttl)
        .def_property(
            "rdata",
            [](const dns_message_t::answer_t& a) {
                return py::bytes(std::string(reinterpret_cast<const char*>(a.rdata.data()),
                                            a.rdata.size()));
            },
            [](dns_message_t::answer_t& a, const std::string& v) {
                a.rdata.assign(v.begin(), v.end());
            });

    py::class_<dns_message_t>(m, "DnsMessage")
        .def(py::init<>())
        .def_readwrite("header", &dns_message_t::header)
        .def_readwrite("questions", &dns_message_t::questions)
        .def_readwrite("answers", &dns_message_t::answers)
        .def_readwrite("authorities", &dns_message_t::authorities)
        .def_readwrite("additional", &dns_message_t::additional)
        .def("add_question", [](dns_message_t& m, const std::string& name, uint16_t qtype,
                                uint16_t qclass) {
            dns_message_t::question_t q;
            q.qname = name;
            q.qtype = qtype;
            q.qclass = qclass;
            m.questions.push_back(q);
        }, py::arg("name"), py::arg("qtype") = 1, py::arg("qclass") = 1)
        .def("to_bytes", &to_bytes<dns_message_t>)
        .def_static("from_bytes", &from_bytes<dns_message_t>)
        .def("__str__", [](const dns_message_t& ms) {
            std::ostringstream ss;
            ss << ms;
            return ss.str();
        });

    py::class_<packet>(m, "Packet")
        .def(py::init<std::size_t>(), py::arg("capacity") = 1500)
        .def("add", [](packet& p, const ethernet_header_t& l) { p.add(l); })
        .def("add", [](packet& p, const ipv4_header_t& l) { p.add(l); })
        .def("add", [](packet& p, const ipv6_header_t& l) { p.add(l); })
        .def("add", [](packet& p, const udp_header_t& l) { p.add(l); })
        .def("add", [](packet& p, const tcp_header_t& l) { p.add(l); })
        .def("add", [](packet& p, const icmp_header_t& l) { p.add(l); })
        .def("add", [](packet& p, const dns_message_t& l) { p.add(l); })
        .def("read_ethernet", [](packet& p) { return p.read<ethernet_header_t>(); })
        .def("read_ipv4", [](packet& p) { return p.read<ipv4_header_t>(); })
        .def("read_ipv6", [](packet& p) { return p.read<ipv6_header_t>(); })
        .def("read_udp", [](packet& p) { return p.read<udp_header_t>(); })
        .def("read_tcp", [](packet& p) { return p.read<tcp_header_t>(); })
        .def("read_icmp", [](packet& p) { return p.read<icmp_header_t>(); })
        .def("read_dns", [](packet& p) { return p.read<dns_message_t>(); })
        .def("size", &packet::size)
        .def("data", [](const packet& p) {
            return py::bytes(std::string(reinterpret_cast<const char*>(p.data()), p.size()));
        })
        .def("clear", &packet::clear);

    py::class_<sniffer>(m, "Sniffer")
        .def(py::init<const std::string&, const std::string&>(), py::arg("dev"),
             py::arg("filter") = "")
        .def("next", [](sniffer& s) -> py::object {
            uint8_t* data = nullptr;
            std::size_t len = 0;
            if (!s.next(data, len)) return py::none();
            return py::bytes(std::string(reinterpret_cast<const char*>(data), len));
        })
        .def_property_readonly("fd", &sniffer::fd);

    py::class_<raw_socket>(m, "RawSocket")
        .def(py::init<const std::string&>(), py::arg("iface"))
        .def("send", [](raw_socket& s, const std::string& data) {
            return s.send(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        })
        .def_property_readonly("fd", &raw_socket::fd);

    m.def("list_interfaces", &list_interfaces);
    m.def("encode_name", [](const std::string& name) {
        auto encoded = encode_name(name);
        return py::bytes(
            std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size()));
    });
    m.def("ipv4_from_string", &ipv4_from_string);
    m.def("ipv4_to_string", &ipv4_to_string);
    m.def("make_dns_query", &make_dns_query, py::arg("hostname"), py::arg("id") = 0x1337,
          py::arg("src_port") = 53000);
}