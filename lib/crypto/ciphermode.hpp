#include <boost/multiprecision/cpp_int.hpp>
#include <crypto/crypto.hpp>
#include <crypto/key.hpp>
#include <vector>

namespace crypto::ciphermode {

using boost::multiprecision::uint128_t;

// don't worry about const qualifier for now.
// TODO: fix qualifier when AES key is integrated
class CipherMode {
    public:
        using AES = AesKey;

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

        // final call to compute the authenticated tag.
        virtual std::vector<uint8_t> final_block() noexcept { return {}; }

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

// GCM
namespace gcm_utils {

constexpr std::size_t IV_SIZE = 12;

// increment the counter bytes (last 4 bytes)
// of `block`
void inc_counter(Buffer&) noexcept;

// make `IV`, with 12 random bytes and
// and 4 bytes counter initialized to 0
Buffer make_gcm_iv() noexcept;

class AuthTag {
    private:
        // Param for Galois auth tag
        const uint128_t H_;

        // XOR last ciphertext to make the tag
        const Buffer counter_0_;

        // starts with 0, since we're not supporting
        // authenticated data right now.
        uint128_t tag_{0};

    public:
        AuthTag(Buffer H, Buffer counter_0)
            : H_{AuthTag::bytes_to_uint128_t(H.block())},
              counter_0_{counter_0} {};

        // Reference: Section 3: The Field `GF(2^128)`
        //
        // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
        void update_tag(const Block& ciphertext);

        // convert 16 byte array in to a 128 bit unsigned integer
        static uint128_t bytes_to_uint128_t(const Block&);
        static void uint128_t_to_bytes(const uint128_t& n, Block&);
        Block tag() const;

    private:
};

}  // namespace gcm_utils

class GCM : CipherMode {
    private:
        gcm_utils::AuthTag tag_;
        std::size_t payload_len_{0};

    public:
        GCM(AES& key, Buffer iv);
        void encrypt_inplace(Buffer& plaintext) noexcept override;
        void decrypt_inplace(Buffer& ciphertext) noexcept override;
        std::vector<uint8_t> final_block() noexcept override;

    private:
        // Since the encryption/decryption of payload is the
        // same, only the auth tag is slightly different...
        void encrypt_general(Buffer& block) noexcept;

        // To encrypt counter 0 for auth tag, and to
        // initialize `H` multiplication variable
        Buffer encrypt_cp(const Buffer& block) noexcept;
};

}  // namespace crypto::ciphermode
