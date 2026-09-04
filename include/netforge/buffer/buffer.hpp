#ifndef NETFORGE_BUFFER_BUFFER_HPP
#define NETFORGE_BUFFER_BUFFER_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include "netforge/buffer/utils.hpp"

namespace netforge {

class buffer {
public:
    buffer() = default;
    buffer(uint8_t* data, std::size_t size);

    uint8_t* data() const noexcept;
    std::size_t size() const noexcept;
    std::size_t position() const noexcept;
    std::size_t remaining() const noexcept;
    bool full() const noexcept;
    bool can_read(std::size_t n) const noexcept;

    void seek(std::size_t pos);
    void skip(std::size_t n);

    template <typename T>
    T consume() {
        if (!can_read(sizeof(T))) throw std::out_of_range("buffer::consume");
        T value;
        std::memcpy(&value, data_ + pos_, sizeof(T));
        pos_ += sizeof(T);
        return utils::ntoh(value);
    }

    template <typename T>
    void produce(T value) {
        if (!can_read(sizeof(T))) throw std::out_of_range("buffer::produce");
        value = utils::ntoh(value);
        std::memcpy(data_ + pos_, &value, sizeof(T));
        pos_ += sizeof(T);
    }

    template <typename T>
    bool try_consume(T& out) noexcept {
        if (!can_read(sizeof(T))) return false;
        std::memcpy(&out, data_ + pos_, sizeof(T));
        pos_ += sizeof(T);
        out = utils::ntoh(out);
        return true;
    }

    uint8_t* consume_bytes(std::size_t n);
    void produce_bytes(const void* src, std::size_t n);

private:
    uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t pos_ = 0;
};

}  // namespace netforge

#endif  // NETFORGE_BUFFER_BUFFER_HPP