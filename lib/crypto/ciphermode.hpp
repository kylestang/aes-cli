#include <crypto/crypto.hpp>
#include <crypto/key.hpp>

namespace crypto::ciphermode {

// don't worry about const qualifier for now.
// TODO: fix qualifier when AES key is integrated
class CipherMode {
    public:
        using AES = Block;

    protected:
        AesKey& key_;
        Buffer diffusion_block_;

        // Kyle: go to ciphermode.cpp and implement these
        void key_encrypt_inplace(Buffer& block) noexcept;
        void key_decrypt_inplace(Buffer& block) noexcept;

    public:
        CipherMode(AES& key, Buffer iv);
        ~CipherMode() = default;

        // encrypt the *padded* block in place
        virtual void encrypt_inplace(Buffer& plaintext) noexcept = 0;

        // decrypt the *padded* block in place
        virtual void decrypt_inplace(Buffer& ciphertext) noexcept = 0;

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
        void encrypt_inplace(Buffer& plaintext) noexcept override;
        void decrypt_inplace(Buffer& ciphertext) noexcept override;
};

class CBC : CipherMode {
    private:
        Buffer diffusion_block_;

    public:
        CBC(AES& key, Buffer iv);
        void encrypt_inplace(Buffer& plaintext) noexcept override;
        void decrypt_inplace(Buffer& ciphertext) noexcept override;
};

class GCM : CipherMode {
    private:
        Buffer diffusion_block_;
        Buffer tag_{};
        const Buffer counter_0_;
        std::size_t payload_len_{0};
        const Buffer H_;

    public:
        GCM(AES& key, Buffer iv);
        void encrypt_inplace(Buffer& plaintext) noexcept override;
        void decrypt_inplace(Buffer& ciphertext) noexcept override;

    private:
        // Since the encryption/decryption of payload is the
        // same, only the auth tag is slightly different...
        void encrypt_general(Buffer& block) noexcept;

        // To encrypt counter 0 for auth tag, and to
        // initialize `H` multiplication variable
        Buffer encrypt_cp(const Buffer& block) noexcept;
};

namespace gcm_utils {

constexpr std::size_t IV_SIZE = 12;

// increment the counter bytes (last 4 bytes)
// of `block`
void inc_counter(Buffer&) noexcept;

// make `IV`, with 12 random bytes and
// and 4 bytes counter initialized to 0
Buffer make_gcm_iv() noexcept;

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
