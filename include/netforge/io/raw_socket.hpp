#ifndef NETFORGE_IO_RAW_SOCKET_HPP
#define NETFORGE_IO_RAW_SOCKET_HPP

#include <cstdint>
#include <string>

namespace netforge {

class raw_socket {
public:
    explicit raw_socket(const std::string& iface);
    ~raw_socket();

    raw_socket(const raw_socket&) = delete;
    raw_socket& operator=(const raw_socket&) = delete;

    int send(const uint8_t* data, std::size_t len) const;
    int fd() const noexcept { return fd_; }

private:
    int fd_ = -1;
    int ifindex_ = -1;
};

}  // namespace netforge

#endif  // NETFORGE_IO_RAW_SOCKET_HPP