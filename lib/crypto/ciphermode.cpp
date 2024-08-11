#include <boost/multiprecision/cpp_int.hpp>
#include <crypto/ciphermode.hpp>
#include <cstdint>
#include <optional>
#include <random>
#include <vector>

namespace crypto::ciphermode {

using BigUint = boost::multiprecision::uint256_t;

// CipherMode abstract class
CipherMode::CipherMode(AES& key, Buffer iv)
    : key_{key}, diffusion_block_{iv} {};

void CipherMode::key_encrypt_inplace(Buffer& block) noexcept {
    // TODO: for Kyle
}

void CipherMode::key_decrypt_inplace(Buffer& block) noexcept {
    // TODO: for Kyle
}

// ECB
ECB::ECB(AES& key) : CipherMode{key, Buffer{}} {}

void ECB::encrypt_inplace(Buffer& block) noexcept {
    key_encrypt_inplace(block);
}

void ECB::decrypt_inplace(Buffer& block) noexcept {
    key_decrypt_inplace(block);
}

// CBC
CBC::CBC(AES& key, Buffer iv) : CipherMode{key, iv} {}

void CBC::encrypt_inplace(Buffer& plaintext) noexcept {
    plaintext ^= diffusion_block_;
    key_encrypt_inplace(plaintext);
    diffusion_block_ = plaintext;  // plaintext is now the ciphertext
}

void CBC::decrypt_inplace(Buffer& ciphertext) noexcept {
    const Buffer new_diff_block = ciphertext;
    key_decrypt_inplace(ciphertext);
    ciphertext ^= diffusion_block_;
    diffusion_block_ = new_diff_block;
}

// GCM
GCM::GCM(AES& key, Buffer iv)
    : CipherMode{key, iv}, tag_{encrypt_cp(Buffer{}), encrypt_cp(iv)} {
    // valid iv/counter buf, where the first 12 bytes are random,
    // but the rest are 0's
    for (uint8_t i = 12; i < diffusion_block_.size(); ++i) {
        assert(diffusion_block_.block()[i] == 0);
    }

    // the actual message starts with counter value 1
    gcm_utils::inc_counter(diffusion_block_);
}

void GCM::encrypt_general(Buffer& m) noexcept {
    Buffer ctr_register{diffusion_block_};
    key_encrypt_inplace(ctr_register);
    m ^= ctr_register;
    gcm_utils::inc_counter(diffusion_block_);
    payload_len_ += m.size();
};

void GCM::encrypt_inplace(Buffer& plaintext) noexcept {
    encrypt_general(plaintext);

    // TODO: compute tag
}

void GCM::decrypt_inplace(Buffer& ciphertext) noexcept {
    encrypt_general(ciphertext);

    // TODO: compute tag
}

Buffer GCM::encrypt_cp(const Buffer& block) noexcept {
    Buffer buf{block};
    encrypt_inplace(buf);
    return buf;
};

std::vector<uint8_t> GCM::final_block() noexcept {
    // TODO: implement this
    return {};
}

namespace gcm_utils {

void inc_counter(Buffer& buffer) noexcept {
    Block& block{buffer.block()};
    for (uint8_t i = BLOCK_SIZE - 1; i >= gcm_utils::IV_SIZE; --i) {
        ++block[i];
        if (block[i] != 0) return;
    }
}

Buffer make_gcm_iv() noexcept {
    Buffer iv{crypto::make_iv(), BLOCK_SIZE};

    // counter bytes, zero values for the last 4 bytes
    Block& block = iv.block();
    for (uint8_t i = IV_SIZE; i < BLOCK_SIZE; ++i) {
        block[i] = 0;
    }

    return iv;
}

uint128_t AuthTag::bytes_to_uint128_t(const Block& bytes) {
    uint128_t result = 0;

    const uint8_t M = bytes.size();
    for (uint8_t i = 0; i < M; ++i) {
        result |= uint128_t(bytes[bytes.size() - 1 - i]) << (i * 8);
    }

    return result;
};

void AuthTag::uint128_t_to_bytes(const uint128_t& n, Block& bytes) {
    const uint8_t M = bytes.size();
    uint128_t bitmask = 0xff;
    for (uint8_t i = 0; i < M; ++i) {
        bytes[i] = uint8_t((n >> ((15 - i) * 8) & 0xff));
    }
};

void AuthTag::update_tag(const Block& ciphertext) {
    // `uint128_t` representation of reduction polynomial:
    // x^127 + x^7 + x^2 + x^1 + 1
    //
    // Since we're doing binary arithmetic in the Galois
    // field with 127 bits, instead of 128, so the last 1
    // is dropped, (thus the hex ends in digit 0.)
    //
    // It is to keep the binary within 127 bits. Math!
    constexpr static uint128_t R = uint128_t(0xE100000000000000) << 64;

    uint128_t ciphertext_value = AuthTag::bytes_to_uint128_t(ciphertext);

    uint128_t bitmask = 1;
    for (uint8_t i = 0; i < 128; ++i) {
        if (H_ & bitmask) {
            tag_ ^= ciphertext_value;
        }

        // if msb is set, xor with R to clamp
        const bool msb_set = (ciphertext_value & (uint128_t(1) << 127)) != 0;
        ciphertext_value <<= 1;

        if (msb_set) {
            ciphertext_value ^= R;
        }

        bitmask <<= 1;
    }
}

Block AuthTag::tag() const {
    Block block{};
    AuthTag::uint128_t_to_bytes(tag_, block);
    return block;
}

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
