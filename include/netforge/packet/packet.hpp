#ifndef NETFORGE_PACKET_PACKET_HPP
#define NETFORGE_PACKET_PACKET_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "netforge/buffer/buffer.hpp"

namespace netforge {

class packet {
public:
    explicit packet(std::size_t capacity = 1500) : storage_(capacity) {}

    template <typename T>
    void add(const T& layer) {
        T copy = layer;
        buffer buf(storage_.data() + write_pos_, storage_.size() - write_pos_);
        copy.produce(buf);
        write_pos_ += buf.position();
    }

    template <typename T>
    T read() {
        buffer buf(storage_.data() + read_pos_, storage_.size() - read_pos_);
        T result = T::consume(buf);
        read_pos_ += buf.position();
        return result;
    }

    std::size_t size() const noexcept { return write_pos_; }
    const uint8_t* data() const noexcept { return storage_.data(); }
    void clear() noexcept { write_pos_ = read_pos_ = 0; }

private:
    std::vector<uint8_t> storage_;
    std::size_t write_pos_ = 0;
    std::size_t read_pos_ = 0;
};

}  // namespace netforge

#endif  // NETFORGE_PACKET_PACKET_HPP