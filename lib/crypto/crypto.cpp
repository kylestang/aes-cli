#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto {
inline const std::size_t BLOCK_SIZE = 16;  // 16 bytes

using Block = std::array<uint8_t, BLOCK_SIZE>;

inline Block& operator^=(Block& left, const Block& right) {
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        left[i] ^= right[i];
    }
    return left;
}

inline Block operator^(const Block& left, const Block& right) {
    Block out{};
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        out[i] = left[i] ^ right[i];
    }
    return out;
}

}  // namespace crypto
