#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto {

// Cipher block, 128 bits (16 bytes)
inline const std::size_t BLOCK_SIZE = 16;

using Block = std::array<uint8_t, BLOCK_SIZE>;

// Initial vector, 96 bits (12 bytes)
inline const std::size_t IV_SIZE = 12;
using IV = std::array<uint8_t, IV_SIZE>;

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

// add padding for a 128 bit block `buf`, with currently `n` size
inline void pad_block(Block& buf, std::size_t n) {
    const uint8_t pad_size = BLOCK_SIZE - n;
    for (std::size_t i = 0; i < pad_size; ++i) {
        buf[BLOCK_SIZE - 1 - i] = pad_size;
    }
}

namespace gcmutils {

// since the nonce is 96 bits (12 bytes), the counter potion is only
// the last 4 bytes. Increment this counter value byte by byte, then wrap
// when the 4th last bit goes from 255 -> 0
inline void block_inc(Block& block) noexcept {
    for (uint8_t i = 15; i >= 12; --i) {
        ++block[i];
        if (block[i] != 0) return;
    }
}
}  // namespace gcmutils

}  // namespace crypto
