#include "netforge/layers/http.hpp"

#include <sstream>

namespace netforge {

std::vector<uint8_t> http_request_t::to_bytes() const {
    std::ostringstream ss;
    ss << method << " " << path << " " << version << "\r\n";
    for (auto& [k, v] : headers)
        ss << k << ": " << v << "\r\n";
    ss << "\r\n";

    std::string head = ss.str();
    std::vector<uint8_t> out(head.begin(), head.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

http_request_t http_request_t::parse(const std::vector<uint8_t>& data) {
    std::string raw(data.begin(), data.end());
    http_request_t req;

    size_t end = raw.find("\r\n");
    if (end == std::string::npos) return req;

    std::string line = raw.substr(0, end);
    size_t p1 = line.find(' ');
    size_t p2 = line.rfind(' ');
    if (p1 != std::string::npos && p2 != std::string::npos && p2 > p1) {
        req.method = line.substr(0, p1);
        req.path = line.substr(p1 + 1, p2 - p1 - 1);
        req.version = line.substr(p2 + 1);
    }

    size_t pos = end + 2;
    while (pos < raw.size()) {
        size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos) break;
        if (eol == pos) { pos += 2; break; }

        std::string hdr = raw.substr(pos, eol - pos);
        size_t colon = hdr.find(':');
        if (colon != std::string::npos) {
            std::string k = hdr.substr(0, colon);
            std::string v = hdr.substr(colon + 2);
            req.headers[k] = v;
        }
        pos = eol + 2;
    }

    if (pos < raw.size())
        req.body.assign(data.begin() + pos, data.end());

    return req;
}

std::ostream& operator<<(std::ostream& out, const http_request_t& r) {
    out << r.method << " " << r.path << " " << r.version << "\r\n";
    for (auto& [k, v] : r.headers)
        out << k << ": " << v << "\r\n";
    out << "\r\n";
    if (!r.body.empty())
        out << "[body: " << r.body.size() << " bytes]";
    return out;
}

std::vector<uint8_t> http_response_t::to_bytes() const {
    std::ostringstream ss;
    ss << version << " " << status_code << " " << status_text << "\r\n";
    for (auto& [k, v] : headers)
        ss << k << ": " << v << "\r\n";
    ss << "\r\n";

    std::string head = ss.str();
    std::vector<uint8_t> out(head.begin(), head.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

http_response_t http_response_t::parse(const std::vector<uint8_t>& data) {
    std::string raw(data.begin(), data.end());
    http_response_t res;

    size_t end = raw.find("\r\n");
    if (end == std::string::npos) return res;

    std::string line = raw.substr(0, end);
    size_t p1 = line.find(' ');
    size_t p2 = line.find(' ', p1 + 1);
    if (p1 != std::string::npos) {
        res.version = line.substr(0, p1);
        res.status_code = std::stoi(line.substr(p1 + 1, p2 - p1 - 1));
        if (p2 != std::string::npos)
            res.status_text = line.substr(p2 + 1);
    }

    size_t pos = end + 2;
    while (pos < raw.size()) {
        size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos) break;
        if (eol == pos) { pos += 2; break; }

        std::string hdr = raw.substr(pos, eol - pos);
        size_t colon = hdr.find(':');
        if (colon != std::string::npos) {
            std::string k = hdr.substr(0, colon);
            std::string v = hdr.substr(colon + 2);
            res.headers[k] = v;
        }
        pos = eol + 2;
    }

    if (pos < raw.size())
        res.body.assign(data.begin() + pos, data.end());

    return res;
}

std::ostream& operator<<(std::ostream& out, const http_response_t& r) {
    out << r.version << " " << r.status_code << " " << r.status_text << "\r\n";
    for (auto& [k, v] : r.headers)
        out << k << ": " << v << "\r\n";
    out << "\r\n";
    if (!r.body.empty())
        out << "[body: " << r.body.size() << " bytes]";
    return out;
}

}  // namespace netforge