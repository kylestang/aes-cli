#include <crypto/crypto.cpp>

namespace crypto::ciphermode {
using crypto::ciphermode::CipherMode;

class ECB : CipherMode {
    public:
        void encrypt_inplace(Block& block) const noexcept override {
        block ^= key_;
        }

        void decrypt_inplace(Block& block) const noexcept override {
        block ^= key_;
        }
};
}  // namespace crypto::ciphermode
