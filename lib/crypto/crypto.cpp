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
}  // namespace crypto::ciphermode
