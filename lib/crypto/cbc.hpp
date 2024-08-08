#include <crypto/crypto.cpp>
#include <random>

namespace crypto::ciphermode {
using crypto::ciphermode::CipherMode;

class CBC : CipherMode {
    private:
        Block diffusion_block_;

    public:
        CBC(const KeyType& key, const Block& iv)
            : CipherMode(key), diffusion_block_{iv} {}

        void encrypt_inplace(Block& plaintext) noexcept override {
            diffusion_block_ ^= key_;
            plaintext ^= diffusion_block_;

            diffusion_block_ = plaintext;  // plaintext is now the ciphertext
        }

        void decrypt_inplace(Block& ciphertext) noexcept override {
            const Block tmp = ciphertext;
            ciphertext ^= key_;
            ciphertext ^= diffusion_block_;
            diffusion_block_ = tmp;
        }
};

class GCM : CipherMode {
    private:
        Block diffusion_block_;
        uint64_t ctr_;
        Block authenticated_tag_{};

    public:
        GCM(const KeyType& key, const Block& iv)
            : CipherMode(key) {
        diffusion_block_ = iv;
        ctr_ = bytes_to_uint64(iv);
    }

        // construction of iv:
        // - [0, 8) byte: random
        // - [8, 16) byte: counter binary
        static Block make_iv() {
            using Distribution =
                std::uniform_int_distribution<std::mt19937::result_type>;

            std::random_device dev;
            std::mt19937 rng{dev()};
            Distribution dist(0, 0xf);

            Block iv{};
            for (std::size_t i = 0; i < BLOCK_SIZE / 2; ++i) {
                iv[i] = dist(rng);
            }

            Distribution rand(0, 0xffffffffffffffff);
            const uint64_t counter = rand(rng);
            uint64_to_bytes(counter, iv);

            return iv;
        }

        void encrypt_inplace(Block& plaintext) noexcept override {
            diffusion_block_ ^= key_;
            plaintext ^= diffusion_block_;
            diffusion_block_ = plaintext;  // plaintext is now the ciphertext
        }

        void decrypt_inplace(Block& ciphertext) noexcept override {
            const Block tmp = ciphertext;
            ciphertext ^= key_;
            ciphertext ^= diffusion_block_;
            diffusion_block_ = tmp;
        }
};
}  // namespace crypto::ciphermode
