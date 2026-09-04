#include "netforge/io/raw_socket.hpp"

#include <cstring>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace netforge {

raw_socket::raw_socket(const std::string& iface) {
    fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ < 0)
        throw std::runtime_error("raw_socket: socket() failed (need root)");

    sockaddr_ll bind_addr{};
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ALL);
    ifindex_ = if_nametoindex(iface.c_str());
    if (ifindex_ == 0) {
        close(fd_);
        fd_ = -1;
        throw std::runtime_error("raw_socket: invalid interface: " + iface);
    }
    bind_addr.sll_ifindex = ifindex_;

    if (bind(fd_, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        close(fd_);
        fd_ = -1;
        throw std::runtime_error("raw_socket: bind() failed");
    }
}

raw_socket::~raw_socket() {
    if (fd_ >= 0) close(fd_);
}

int raw_socket::send(const uint8_t* data, std::size_t len) const {
    sockaddr_ll dest{};
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = ifindex_;
    dest.sll_halen = 6;
    std::memcpy(dest.sll_addr, data, 6);
    return static_cast<int>(
        sendto(fd_, data, len, 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)));
}

}  // namespace netforge