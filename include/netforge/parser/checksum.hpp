#ifndef NETFORGE_PARSER_CHECKSUM_HPP
#define NETFORGE_PARSER_CHECKSUM_HPP

#include <cstddef>
#include <cstdint>

namespace netforge {
namespace checksum {

uint16_t compute(const uint8_t* data, std::size_t len, uint32_t start = 0);
bool verify(const uint8_t* data, std::size_t len, uint32_t start = 0);

}  // namespace checksum
}  // namespace netforge

#endif  // NETFORGE_PARSER_CHECKSUM_HPP