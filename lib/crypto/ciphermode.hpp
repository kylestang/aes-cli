#include <boost/multiprecision/cpp_int.hpp>
#include <crypto/crypto.hpp>
#include <crypto/key.hpp>

namespace crypto::ciphermode {

using boost::multiprecision::uint128_t;

// don't worry about const qualifier for now.
// TODO: fix qualifier when AES key is integrated
class CipherMode {
    public:
        using AES = AesKey;

    protected:
        AesKey& key_;
        std::istream& input_fd_;
        std::ostream& output_fd_;
        Block diffusion_block_;

        virtual void key_encrypt_inplace(Block& buf) noexcept;
        virtual void key_decrypt_inplace(Block& buf) noexcept;

    public:
        CipherMode(AES& key, std::istream& in, std::ostream& out, Block& iv);
        ~CipherMode() = default;

        virtual void encrypt(Block&) noexcept = 0;
        virtual void decrypt(Block&) noexcept = 0;

        void encrypt_fd() noexcept;
        void decrypt_fd() noexcept;

        // final call to compute the authenticated tag.
        virtual std::vector<char> tag() noexcept { return {}; }

        // don't need these
        CipherMode() = delete;
        CipherMode(CipherMode&) = delete;
        CipherMode(CipherMode&&) = delete;
        CipherMode& operator=(CipherMode&) = delete;
        CipherMode& operator=(CipherMode&&) = delete;
};

class ECB : public CipherMode {
    public:
        ECB(AES& key, std::istream& in, std::ostream& out, Block& iv);
        void encrypt(Block& buf) noexcept override;
        void decrypt(Block& buf) noexcept override;
};

class CBC : public CipherMode {
    public:
        CBC(AES& key, std::istream& in, std::ostream& out, Block& iv);
        void encrypt(Block& buf) noexcept override;
        void decrypt(Block& buf) noexcept override;
};

// GCM
namespace gcm_utils {

constexpr std::size_t IV_SIZE = 12;

// increment the counter bytes (last 4 bytes)
// of `block`
void inc_counter(Block&) noexcept;

class AuthTag {
    private:
        // Param for Galois auth tag
        const uint128_t H_;

        // XOR last ciphertext to make the tag
        const Block counter_0_;

        // starts with 0, since we're not supporting
        // authenticated data right now.
        uint128_t tag_{0};

    public:
        AuthTag(Block H, Block counter_0)
            : H_{AuthTag::bytes_to_uint128_t(H)},
              counter_0_{counter_0} {};

        const uint128_t& H() const noexcept;

        void update_tag(const Block& ciphertext);
        uint128_t counter0() const noexcept;

        // convert 16 byte array in to a 128 bit unsigned integer
        static uint128_t bytes_to_uint128_t(const Block&);
        static void uint128_t_to_bytes(const uint128_t& n, Block&);
        uint128_t value() const noexcept;
        static uint128_t galois_multiply(const uint128_t&, const uint128_t&);
};

}  // namespace gcm_utils

class GCM : public CipherMode {
    private:
        gcm_utils::AuthTag tag_;
        uint64_t payload_len_{0};
        uint64_t aad_len_{0};

    public:
        GCM(AES& key, std::istream& in, std::ostream& out, Block& iv);
        void encrypt(Block& buf) noexcept override;
        void decrypt(Block& buf) noexcept override;
        std::vector<char> tag() noexcept override;

    private:
        // Since the encryption/decryption of payload is the
        // same, only the auth tag is slightly different...
        void encrypt_general(Block& block) noexcept;

        // To encrypt counter 0 for auth tag, and to
        // initialize `H` multiplication variable
        Block encrypt_cp(const Block& block) noexcept;
};

}  // namespace crypto::ciphermode
