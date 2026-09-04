#include "netforge/buffer/buffer.hpp"

#include <cstring>
#include <stdexcept>

namespace netforge {

buffer::buffer(uint8_t* data, std::size_t size) : data_(data), size_(size) {}

uint8_t* buffer::data() const noexcept { return data_; }

std::size_t buffer::size() const noexcept { return size_; }

std::size_t buffer::position() const noexcept { return pos_; }

std::size_t buffer::remaining() const noexcept { return size_ - pos_; }

bool buffer::full() const noexcept { return pos_ >= size_; }

bool buffer::can_read(std::size_t n) const noexcept { return remaining() >= n; }

void buffer::seek(std::size_t pos) {
    if (pos > size_) throw std::out_of_range("buffer::seek");
    pos_ = pos;
}

void buffer::skip(std::size_t n) {
    if (!can_read(n)) throw std::out_of_range("buffer::skip");
    pos_ += n;
}

uint8_t* buffer::consume_bytes(std::size_t n) {
    if (!can_read(n)) throw std::out_of_range("buffer::consume_bytes");
    uint8_t* ptr = data_ + pos_;
    pos_ += n;
    return ptr;
}

void buffer::produce_bytes(const void* src, std::size_t n) {
    if (!can_read(n)) throw std::out_of_range("buffer::produce_bytes");
    std::memcpy(data_ + pos_, src, n);
    pos_ += n;
}

}  // namespace netforge