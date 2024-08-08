#include <array>
#include <crypto/crypto.cpp>
#include <cstdint>
#include <random>

namespace crypto::ciphermode {

using crypto::BLOCK_SIZE;
using Block = std::array<uint8_t, BLOCK_SIZE>;

// write `num` in big endian bytes to the last 8 bytes for `buf`
void uint64_to_be_bytes(uint64_t num, Block buf) noexcept;

// read (big endian) the last 8 bytes of `buf`
uint64_t be_bytes_to_uint64(Block buf) noexcept;

// Don't worry about const qualifier for now.
// TODO: fix qualifier when AES key is integrated
class CipherMode {
    public:
        using AES = Block;  // TODO: Kyle change this type

    protected:
        AES& key_;  // Kyle update this key to your AES class
        Block diffusion_block_;

        // Kyle: go to ciphermode.cpp and implement these
        void key_encrypt(Block& block) noexcept;
        void key_decrypt(Block& block) noexcept;

    public:
        CipherMode(AES& key, Block iv = {});
        ~CipherMode() = default;

        const AES& key() const noexcept { return key_; };
        virtual void encrypt_inplace(Block& plaintext) noexcept;
        virtual void decrypt_inplace(Block& ciphertext) noexcept;

        Block make_iv() noexcept;

        CipherMode() = delete;
        CipherMode(CipherMode&) = delete;
        CipherMode(CipherMode&&) = delete;
        CipherMode& operator=(CipherMode&) = delete;
        CipherMode& operator=(CipherMode&&) = delete;
};

class ECB : CipherMode {
    public:
        ECB(AES&);
        void encrypt_inplace(Block& plaintext) noexcept override;
        void decrypt_inplace(Block& ciphertext) noexcept override;
};

class CBC : CipherMode {
    private:
        Block diffusion_block_;

    public:
        CBC(AES& key, Block iv);
        void encrypt_inplace(Block& plaintext) noexcept override;
        void decrypt_inplace(Block& ciphertext) noexcept override;
};

class GCM : CipherMode {
    private:
        Block diffusion_block_;
        Block tag_{};
        void inc_counter() noexcept;

    public:
        GCM(AES& key, Block iv);
        void encrypt_inplace(Block& plaintext) noexcept override;
        void decrypt_inplace(Block& ciphertext) noexcept override;
};
}  // namespace crypto::ciphermode
