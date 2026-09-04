#pragma once

#include <cstdint>
#include <cstring>
namespace netforge {
namespace utils {

inline uint32_t ntoh(uint32_t value) {
        return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
               (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
}

inline uint16_t ntoh(uint16_t value) { return (value & 0x00FF) << 8 | (value & 0xFF00) >> 8; }

inline uint8_t ntoh(uint8_t value) { return value; }

inline uint32_t sum_every_16bits(uint8_t* addr, int count) {
        uint32_t sum = 0;
        uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);
        while (count > 1) {
                sum += *ptr++;
                count -= 2;
        }
        if (count > 0) sum += *(uint8_t*)ptr;
        return sum;
}

inline uint16_t checksum(uint8_t* addr, int count, int start_sum) {
        uint32_t sum = start_sum;
        sum += sum_every_16bits(addr, count);
        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);
        uint16_t ret = ~sum;
        return ntoh(ret);
}

};  // namespace utils
};  // namespace netforge