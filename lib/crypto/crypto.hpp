#pragma once
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <vector>

namespace crypto {

// Cipher block, 128 bits (16 bytes)
inline constexpr const std::size_t BLOCK_SIZE = 16;
using Block = std::array<uint8_t, BLOCK_SIZE>;

Block& operator^=(Block& l, const Block& r);
Block operator^(const Block& l, const Block& r);

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

struct Buffer : public std::vector<uint8_t> {
    public:
        using Bytes = std::vector<uint8_t>;

    public:
        Buffer(){};
        Buffer(Block block, std::size_t n);
        Buffer(const Buffer&) = default;
        ~Buffer() = default;

        Buffer& operator^=(const Buffer& other) noexcept;
        Buffer operator^(const Buffer& other) const noexcept;

        Block block() const noexcept;

        Bytes& bytes() noexcept;
        const Bytes& bytes() const noexcept;

        // PKCS7 padding for a 128 bit block `buf_`
        void pad_pkcs7() noexcept;
        void rm_pad_pkcs7() noexcept;
};

// Initial vector, 96 bits (12 bytes)
constexpr const std::size_t IV_SIZE = 12;
using IV = std::array<uint8_t, IV_SIZE>;

namespace gcmutils {

// since the nonce is 96 bits (12 bytes), the counter potion is only
// the last 4 bytes. Increment this counter value byte by byte, then wrap
// when the 4th last bit goes from 255 -> 0
void block_inc(Block& block) noexcept;

}  // namespace gcmutils

}  // namespace crypto
