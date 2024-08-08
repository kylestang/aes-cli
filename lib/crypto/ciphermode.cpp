#include <crypto/ciphermode.hpp>
#include <cstdint>

namespace crypto::ciphermode {

void uint64_to_be_bytes(uint64_t num, Block buf) noexcept {
    buf[15] = (num & 0x00000000000000ff);
    buf[14] = (num & 0x000000000000ff00) >> 8;
    buf[13] = (num & 0x0000000000ff0000) >> 16;
    buf[12] = (num & 0x00000000ff000000) >> 24;
    buf[11] = (num & 0x000000ff00000000) >> 32;
    buf[10] = (num & 0x0000ff0000000000) >> 40;
    buf[9] = (num & 0x00ff000000000000) >> 48;
    buf[8] = (num & 0xff00000000000000) >> 56;
}

uint64_t be_bytes_to_uint64(Block buf) noexcept {
    uint64_t out = 0;

    out |= (uint64_t(buf[8]) << 56);
    out |= (uint64_t(buf[9]) << 48);
    out |= (uint64_t(buf[10]) << 40);
    out |= (uint64_t(buf[11]) << 32);
    out |= (uint64_t(buf[12]) << 24);
    out |= (uint64_t(buf[13]) << 16);
    out |= (uint64_t(buf[14]) << 8);
    out |= uint64_t(buf[15]);

    return out;
}

// CipherMode abstract class
CipherMode::CipherMode(AES& key, Block iv) : key_{key}, diffusion_block_{iv} {};

Block CipherMode::make_iv() noexcept {
    using Distribution =
        std::uniform_int_distribution<std::mt19937::result_type>;

    std::random_device dev;
    std::mt19937 rng{dev()};
    Distribution dist(0, 0xf);

    Block iv{};
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        iv[i] = dist(rng);
    }
    return iv;
}

void CipherMode::key_encrypt(Block& block) noexcept {
    // TODO: for Kyle
}

void CipherMode::key_decrypt(Block& block) noexcept {
    // TODO: for Kyle
}

// ECB
ECB::ECB(AES& key) : CipherMode{key} {}
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

void GCM::inc_counter() noexcept {
    uint64_t counter = be_bytes_to_uint64(diffusion_block_);
    uint64_to_be_bytes(++counter, diffusion_block_);
}

void GCM::encrypt_inplace(Block& plaintext) noexcept {
    Block ctr_register{diffusion_block_};
    key_encrypt(ctr_register);
    plaintext ^= ctr_register;
    inc_counter();

    // TODO: compute tag
}

void GCM::decrypt_inplace(Block& ciphertext) noexcept {
    encrypt_inplace(ciphertext);  // actually the same logic for encrypt/decrypt
}

}  // namespace crypto::ciphermode
