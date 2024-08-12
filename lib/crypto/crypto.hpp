#pragma once
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <random>
#include <stdexcept>

namespace crypto {

// Cipher block, 128 bits (16 bytes)
inline constexpr const std::size_t BLOCK_SIZE = 16;
using Block = std::array<unsigned char, BLOCK_SIZE>;

Block& operator^=(Block& l, const Block& r);
Block operator^(const Block& l, const Block& r);

inline void pad_pkcs7(Block& buf, std::size_t n) {
    const uint8_t pad_size = BLOCK_SIZE - n;
    for (std::size_t i = 0; i < pad_size; ++i) {
        buf[(BLOCK_SIZE - 1 - i)] = pad_size;
    }
}

// returns how many bytes there are remaining
inline std::size_t rm_pad_pkcs7(Block& block) {
    const uint8_t pad_size = block[BLOCK_SIZE - 1];
    if (pad_size > BLOCK_SIZE) return BLOCK_SIZE;  // no padding

    // valid padding?
    for (uint8_t i = 0; i < pad_size; ++i) {
        if (block[BLOCK_SIZE - 1 - i] != pad_size) return BLOCK_SIZE;
    }

    for (uint8_t i = 0; i < pad_size; ++i) {
        block[BLOCK_SIZE - 1 - i] = 0;
    }

    return BLOCK_SIZE - pad_size;
}

// fill upto `n` bytes, where `n <= BLOCK_SIZE`
inline void fill_bytes_n(Block& buf, uint8_t n) {
    if (n > BLOCK_SIZE) {
        throw std::logic_error{"byte count `n` exceeds `buf` size."};
    }

    std::random_device dev;
    std::mt19937 rng{dev()};
    std::uniform_int_distribution<std::mt19937::result_type> dist{0, 0xff};

    for (uint8_t i = 0; i < n; ++i) {
        buf[i] = dist(rng);
    }
}

// Initial vector, 96 bits (12 bytes)
constexpr const std::size_t IV_SIZE = 12;

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
