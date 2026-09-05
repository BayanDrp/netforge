#ifndef NETFORGE_IO_SNIFFER_HPP
#define NETFORGE_IO_SNIFFER_HPP

#include <cstdint>
#include <string>
#include <vector>

typedef struct pcap pcap_t;

namespace netforge {

class sniffer {
public:
    explicit sniffer(const std::string& dev, const std::string& filter = "");
    ~sniffer();

    sniffer(const sniffer&) = delete;
    sniffer& operator=(const sniffer&) = delete;

    bool next(uint8_t*& data, std::size_t& len);
    int fd() const noexcept { return fd_; }

private:
    pcap_t* handle_ = nullptr;
    int fd_ = -1;
};

std::vector<std::string> list_interfaces();

}  // namespace netforge

#endif  // NETFORGE_IO_SNIFFER_HPP