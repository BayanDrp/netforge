#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include "netforge/buffer/utils.hpp"

namespace netforge {

class buffer {
public:
    buffer() = default;
    buffer(uint8_t* data, std::size_t size) : data_(data), size_(size) {}

    uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    std::size_t position() const noexcept { return pos_; }
    std::size_t remaining() const noexcept { return size_ - pos_; }
    bool full() const noexcept { return pos_ >= size_; }
    bool can_read(std::size_t n) const noexcept { return remaining() >= n; }

    void seek(std::size_t pos) {
        if (pos > size_) throw std::out_of_range("buffer::seek");
        pos_ = pos;
    }

    void skip(std::size_t n) {
        if (!can_read(n)) throw std::out_of_range("buffer::skip");
        pos_ += n;
    }

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

    uint8_t* consume_bytes(std::size_t n) {
        if (!can_read(n)) throw std::out_of_range("buffer::consume_bytes");
        uint8_t* ptr = data_ + pos_;
        pos_ += n;
        return ptr;
    }

    void produce_bytes(const void* src, std::size_t n) {
        if (!can_read(n)) throw std::out_of_range("buffer::produce_bytes");
        std::memcpy(data_ + pos_, src, n);
        pos_ += n;
    }

private:
    uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t pos_ = 0;
};

}  // namespace netforge