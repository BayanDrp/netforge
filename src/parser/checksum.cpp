#include "netforge/parser/checksum.hpp"

#include "netforge/buffer/utils.hpp"

namespace netforge {
namespace checksum {

uint16_t compute(const uint8_t* data, std::size_t len, uint32_t start) {
    return utils::checksum(const_cast<uint8_t*>(data), static_cast<int>(len),
                           static_cast<int>(start));
}

bool verify(const uint8_t* data, std::size_t len, uint32_t start) {
    return compute(data, len, start) == 0;
}

}  // namespace checksum
}  // namespace netforge