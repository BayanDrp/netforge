#include "netforge/io/sniffer.hpp"

#include <pcap/pcap.h>

#include <stdexcept>
#include <string>

namespace netforge {

sniffer::sniffer(const std::string& dev, const std::string& filter) {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    handle_ = pcap_open_live(dev.c_str(), 65535, 1, 1000, errbuf);
    if (handle_ == nullptr)
        throw std::runtime_error("sniffer: pcap_open_live() failed: " + std::string(errbuf));

    if (!filter.empty()) {
        bpf_program prog{};
        if (pcap_compile(handle_, &prog, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            std::string msg =
                "sniffer: pcap_compile() failed: " + std::string(pcap_geterr(handle_));
            pcap_close(handle_);
            handle_ = nullptr;
            throw std::runtime_error(msg);
        }
        if (pcap_setfilter(handle_, &prog) < 0) {
            std::string msg =
                "sniffer: pcap_setfilter() failed: " + std::string(pcap_geterr(handle_));
            pcap_freecode(&prog);
            pcap_close(handle_);
            handle_ = nullptr;
            throw std::runtime_error(msg);
        }
        pcap_freecode(&prog);
    }

    fd_ = pcap_get_selectable_fd(handle_);
}

sniffer::~sniffer() {
    if (handle_ != nullptr) pcap_close(handle_);
}

bool sniffer::next(uint8_t*& data, std::size_t& len) {
    pcap_pkthdr* hdr = nullptr;
    const uint8_t* pkt = nullptr;
    int ret;
    while ((ret = pcap_next_ex(handle_, &hdr, &pkt)) == 0) {
    }
    if (ret < 0 || hdr == nullptr || pkt == nullptr) {
        data = nullptr;
        len = 0;
        return false;
    }
    data = const_cast<uint8_t*>(pkt);
    len = hdr->caplen;
    return true;
}

std::vector<std::string> list_interfaces() {
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE]{};
    if (pcap_findalldevs(&alldevs, errbuf) < 0)
        throw std::runtime_error("sniffer: pcap_findalldevs() failed: " + std::string(errbuf));

    std::vector<std::string> names;
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) names.push_back(dev->name);
    pcap_freealldevs(alldevs);
    return names;
}

}  // namespace netforge