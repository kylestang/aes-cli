#include <crypto/crypto.cpp>

namespace crypto::ciphermode {

// don't worry about const qualifier for now.
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

        // encrypt the *padded* block in place
        virtual void encrypt_inplace(Block& plaintext) noexcept = 0;

        // decrypt the *padded* block in place
        virtual void decrypt_inplace(Block& ciphertext) noexcept = 0;

        // don't need these
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

// increment the counter bytes (last 4 bytes)
// of `block`
void inc_counter(Block&) noexcept;

// make `IV`, with 12 random bytes and
// and 4 bytes counter initialized to 0
Block make_gcm_iv() noexcept;

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
