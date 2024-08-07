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
    
        CipherMode(const KeyType& key) {}
        ~CipherMode() = default;

        virtual void encrypt_inplace(Block& block) const noexcept;
        virtual void decrypt_inplace(Block& block) const noexcept;

        CipherMode() = delete;
        CipherMode(CipherMode&) = delete;
        CipherMode(CipherMode&&) = delete;
        CipherMode& operator=(CipherMode&) = delete;
        CipherMode& operator=(CipherMode&&) = delete;
};
}  // namespace crypto::ciphermode
