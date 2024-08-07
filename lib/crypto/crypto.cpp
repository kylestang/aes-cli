#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto {
const std::size_t BLOCK_SIZE = 16;  // 16 bytes
using Block = std::array<uint8_t, BLOCK_SIZE>;
}  // namespace crypto

namespace crypto::ciphermode {
class CipherMode {
    public:
        using KeyType = Block;  // TODO: ask Kyle if this is
                                // the right type
    protected:
        const KeyType& key_;

        void xor_block(Block& block_mut, const Block& block) const {
            for (std::size_t i = 0; i < block.size(); ++i) {
                block_mut[i] ^= block[i];
            }
        };

    public:
        CipherMode(const KeyType& key) : key_{key} {};
        ~CipherMode() = default;

        const KeyType& key() const noexcept { return key_; };
        virtual void encrypt_inplace(Block& block) const noexcept;
        virtual void decrypt_inplace(Block& block) const noexcept;

        CipherMode() = delete;
        CipherMode(CipherMode&) = delete;
        CipherMode(CipherMode&&) = delete;
        CipherMode& operator=(CipherMode&) = delete;
        CipherMode& operator=(CipherMode&&) = delete;
};
}  // namespace crypto::ciphermode
