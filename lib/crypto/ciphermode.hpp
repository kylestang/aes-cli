#include <crypto/crypto.cpp>
#include <cstdint>

namespace crypto::ciphermode {

// write `num` in big endian bytes to the last 8 bytes for `buf`
void uint64_to_be_bytes(uint64_t num, Block buf) noexcept;

// read (big endian) the last 8 bytes of `buf`
uint64_t be_bytes_to_uint64(const Block& buf) noexcept;

void block_inc(Block& block) noexcept;

// Don't worry about const qualifier for now.
// TODO: fix qualifier when AES key is integrated
class CipherMode {
    public:
        using AES = Block;  // TODO: Kyle change this type

    protected:
        AES& key_;  // Kyle update this key to your AES class
        Block diffusion_block_;

        // Kyle: go to ciphermode.cpp and implement these
        void key_encrypt_inplace(Block& block) noexcept;
        void key_decrypt_inplace(Block& block) noexcept;

    public:
        CipherMode(AES& key, Block iv);
        ~CipherMode() = default;

        virtual void encrypt_inplace(Block& plaintext) noexcept = 0;
        virtual void decrypt_inplace(Block& ciphertext) noexcept = 0;

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
        const Block counter_0_;
        std::size_t payload_len_{0};
    const Block H_;

    public:
        GCM(AES& key, Block iv);
        void encrypt_inplace(Block& plaintext) noexcept override;
        void decrypt_inplace(Block& ciphertext) noexcept override;

    private:
        // Since the encryption/decryption of payload is the
        // same, only the auth tag is slightly different...
        void encrypt_general(Block& block) noexcept;

        // To encrypt counter 0 for auth tag, and to
        // initialize `H` multiplication variable
        Block encrypt_cp(const Block& block) noexcept;
};

namespace gcm_utils {

constexpr std::size_t IV_SIZE = 12;

void inc_counter(Block&) noexcept;

Block make_gcm_iv() noexcept;

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
