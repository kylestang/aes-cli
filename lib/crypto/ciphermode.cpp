#include <crypto/ciphermode.hpp>
#include <cstdint>
#include <random>

namespace crypto::ciphermode {

// CipherMode abstract class
CipherMode::CipherMode(AES& key, Block iv) : key_{key}, diffusion_block_{iv} {};

void CipherMode::key_encrypt_inplace(Block& block) noexcept {
    // TODO: for Kyle
}

void CipherMode::key_decrypt_inplace(Block& block) noexcept {
    // TODO: for Kyle
}

// ECB
ECB::ECB(AES& key) : CipherMode{key, Block{}} {}

void ECB::encrypt_inplace(Block& block) noexcept { key_encrypt_inplace(block); }

void ECB::decrypt_inplace(Block& block) noexcept { key_decrypt_inplace(block); }

// CBC
CBC::CBC(AES& key, Block iv) : CipherMode{key, iv} {}

void CBC::encrypt_inplace(Block& plaintext) noexcept {
    plaintext ^= diffusion_block_;
    key_encrypt_inplace(plaintext);
    diffusion_block_ = plaintext;  // plaintext is now the ciphertext
}

void CBC::decrypt_inplace(Block& ciphertext) noexcept {
    const Block new_diff_block = ciphertext;
    key_decrypt_inplace(ciphertext);
    ciphertext ^= diffusion_block_;
    diffusion_block_ = new_diff_block;
}

// GCM
GCM::GCM(AES& key, Block iv)
    : CipherMode{key, iv}, counter_0_{encrypt_cp(iv)}, H_{encrypt_cp(Block{})} {
    key_encrypt_inplace(tag_);

    // the actual message starts with counter value 1
    gcm_utils::inc_counter(diffusion_block_);
}

void GCM::encrypt_general(Block& m) noexcept {
    Block ctr_register{diffusion_block_};
    key_encrypt_inplace(ctr_register);
    m ^= ctr_register;
    gcm_utils::inc_counter(diffusion_block_);
};

void GCM::encrypt_inplace(Block& plaintext) noexcept {
    encrypt_general(plaintext);

    // TODO: compute tag
    payload_len_ += plaintext.size();
}

void GCM::decrypt_inplace(Block& ciphertext) noexcept {
    encrypt_general(ciphertext);

    // TODO: compute tag
    payload_len_ += ciphertext.size();
}

Block GCM::encrypt_cp(const Block& block) noexcept {
    Block buf{block};
    encrypt_inplace(buf);
    return buf;
};

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
    for (uint8_t i = 0; i < gcm_utils::IV_SIZE; ++i) {
        iv[i] = dist(rng);
    }

    return iv;
}

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
