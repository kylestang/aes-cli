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

namespace crypto::ciphermode {
class CipherMode {
    public:
        using KeyType = Block;  // TODO: ask Kyle if this is
                                // the right type
    protected:
        const KeyType& key_;

    public:
        CipherMode(const KeyType& key) : key_{key} {};
        ~CipherMode() = default;

        const KeyType& key() const noexcept { return key_; };
        virtual void encrypt_inplace(Block& plaintext) noexcept;
        virtual void decrypt_inplace(Block& ciphertext) noexcept;

        CipherMode() = delete;
        CipherMode(CipherMode&) = delete;
        CipherMode(CipherMode&&) = delete;
        CipherMode& operator=(CipherMode&) = delete;
        CipherMode& operator=(CipherMode&&) = delete;
};

// convert `num` to bytes then write to the last 8 bytes of `buf`.
// bytes in big endian representation
void uint64_to_bytes(uint64_t num, Block buf) {
    buf[15] = (num & 0x00000000000000ff);
    buf[14] = (num & 0x000000000000ff00) >> 8;
    buf[13] = (num & 0x0000000000ff0000) >> 16;
    buf[12] = (num & 0x00000000ff000000) >> 24;
    buf[11] = (num & 0x000000ff00000000) >> 32;
    buf[10] = (num & 0x0000ff0000000000) >> 40;
    buf[9] = (num & 0x00ff000000000000) >> 48;
    buf[8] = (num & 0xff00000000000000) >> 56;
}

// convert the last 8 bytes of `buf` to uint64_t
// bytes in big endian representation
uint64_t bytes_to_uint64(Block buf) {
    uint64_t out = 0;

    for (std::size_t i = 0; i < 8; ++i) {
        out += buf[15 - i] << (i * 8);
    }

    return out;
}
}  // namespace crypto::ciphermode
