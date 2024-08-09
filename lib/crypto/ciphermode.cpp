#include <crypto/ciphermode.hpp>
#include <cstdint>
#include <random>

namespace crypto::ciphermode {

// CipherMode abstract class
CipherMode::CipherMode(AES& key, Block iv) : key_{key}, diffusion_block_{iv} {};

void CipherMode::key_encrypt(Block& block) noexcept {
    // TODO: for Kyle
}

void CipherMode::key_decrypt(Block& block) noexcept {
    // TODO: for Kyle
}

// ECB
ECB::ECB(AES& key) : CipherMode{key, Block{}} {}

void ECB::encrypt_inplace(Block& block) noexcept { key_encrypt(block); }

void ECB::decrypt_inplace(Block& block) noexcept { key_decrypt(block); }

// CBC
CBC::CBC(AES& key, Block iv) : CipherMode{key, iv} {}

void CBC::encrypt_inplace(Block& plaintext) noexcept {
    plaintext ^= diffusion_block_;
    key_encrypt(plaintext);
    diffusion_block_ = plaintext;  // plaintext is now the ciphertext
}

void CBC::decrypt_inplace(Block& ciphertext) noexcept {
    const Block new_diff_block = ciphertext;
    key_decrypt(ciphertext);
    ciphertext ^= diffusion_block_;
    diffusion_block_ = new_diff_block;
}

// GCM
GCM::GCM(AES& key, Block iv) : CipherMode{key, iv} {}

void GCM::encrypt_inplace(Block& plaintext) noexcept {
    Block ctr_register{diffusion_block_};
    key_encrypt(ctr_register);
    plaintext ^= ctr_register;
    gcm_utils::inc_counter(diffusion_block_);

    // TODO: compute tag
}

void GCM::decrypt_inplace(Block& ciphertext) noexcept {
    encrypt_inplace(ciphertext);  // actually the same logic for encrypt/decrypt
}

namespace gcm_utils {
void inc_counter(Block& block) noexcept {
    for (uint8_t i = BLOCK_SIZE - 1; i >= gcm_utils::IV_SIZE; --i) {
        ++block[i];
        if (block[i] != 0) return;
    }
}

Block make_gcm_iv() noexcept {
    std::random_device dev;
    std::mt19937 rng{dev()};
    std::uniform_int_distribution<std::mt19937::result_type> dist{0, 0xff};

    Block iv{};
    for (uint8_t i = 0 ; i < gcm_utils::IV_SIZE; ++i) {
        iv[i] = dist(rng);
    }

    return iv;
}

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
