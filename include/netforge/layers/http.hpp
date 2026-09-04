#pragma once

#include <cstdint>
#include <map>
#include <ostream>
#include <string>
#include <vector>

namespace netforge {

struct http_request_t {
    std::string method{"GET"};
    std::string path{"/"};
    std::string version{"HTTP/1.1"};
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;

    std::vector<uint8_t> to_bytes() const;
    static http_request_t parse(const std::vector<uint8_t>& data);

    friend std::ostream& operator<<(std::ostream& out, const http_request_t& r);
};

struct http_response_t {
    std::string version;
    int status_code{0};
    std::string status_text;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;

    std::vector<uint8_t> to_bytes() const;
    static http_response_t parse(const std::vector<uint8_t>& data);

    friend std::ostream& operator<<(std::ostream& out, const http_response_t& r);
};

}  // namespace netforge