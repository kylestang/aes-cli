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

inline void pad_(uint8_t* buf, std::size_t full_block_size,
                 std::size_t pad_size) {
    for (std::size_t i = 0; i < pad_size; ++i) {
        buf[full_block_size - 1 - i] = pad_size;
    }
};

// add padding for a 128 bit block `buf`
inline void pad_block(crypto::Block& buf) {
    pad_(buf.begin(), crypto::BLOCK_SIZE, crypto::BLOCK_SIZE - buf.size());
}

inline void uint64_to_be_bytes(uint64_t num, Block& buf) noexcept {
    buf[15] = (num & 0x00000000000000ff);
    buf[14] = (num & 0x000000000000ff00) >> 8;
    buf[13] = (num & 0x0000000000ff0000) >> 16;
    buf[12] = (num & 0x00000000ff000000) >> 24;
    buf[11] = (num & 0x000000ff00000000) >> 32;
    buf[10] = (num & 0x0000ff0000000000) >> 40;
    buf[9] = (num & 0x00ff000000000000) >> 48;
    buf[8] = (num & 0xff00000000000000) >> 56;
}

inline uint64_t be_bytes_to_uint64(const Block& buf) noexcept {
    uint64_t out = 0;

    out |= (uint64_t(buf[8]) << 56);
    out |= (uint64_t(buf[9]) << 48);
    out |= (uint64_t(buf[10]) << 40);
    out |= (uint64_t(buf[11]) << 32);
    out |= (uint64_t(buf[12]) << 24);
    out |= (uint64_t(buf[13]) << 16);
    out |= (uint64_t(buf[14]) << 8);
    out |= uint64_t(buf[15]);

    return out;
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
