#include <boost/multiprecision/cpp_int.hpp>
#include <crypto/ciphermode.hpp>
#include <cstdint>

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

Buffer ECB::encrypt(const Buffer& plaintext) noexcept {
    Buffer ciphertext{plaintext};
    key_encrypt_inplace(ciphertext);
    return ciphertext;
}

Buffer ECB::decrypt(const Buffer& ciphertext) noexcept {
    Buffer plaintext{ciphertext};
    key_decrypt_inplace(plaintext);
    return plaintext;
}

// CBC
CBC::CBC(AES& key, Buffer iv) : CipherMode{key, iv} {}

Buffer CBC::encrypt(const Buffer& plaintext) noexcept {
    Buffer ciphertext{plaintext};
    ciphertext ^= diffusion_block_;
    key_encrypt_inplace(ciphertext);
    diffusion_block_ = ciphertext;
    return ciphertext;
}

Buffer CBC::decrypt(const Buffer& ciphertext) noexcept {
    Buffer plaintext{ciphertext};
    key_decrypt_inplace(plaintext);
    plaintext ^= diffusion_block_;
    diffusion_block_ = ciphertext;
    return plaintext;
}

// GCM:
//
// This implementation:
//
// 1. Does not support the additional authenticated data (`aad`),
//    so it is defaults to an empty vector.
//
// 2. The `IV` has 12 random bytes, and the last 4 bytes should
//    be initialized to zeros, these are the counter bytes.
GCM::GCM(AES& key, Buffer iv, Buffer aad)
    : CipherMode{key, iv},
      tag_{encrypt_cp(Buffer{}), encrypt_cp(iv)},
      aad_len_{aad.size()} {
    // valid iv/counter buf, where the first 12 bytes are random,
    // but the rest are 0's
    for (uint8_t i = 12; i < diffusion_block_.size(); ++i) {
        assert(diffusion_block_.at(i) == 0);
    }

    // the actual message starts with counter value 1
    gcm_utils::inc_counter(diffusion_block_);
    tag_.update_tag(aad.block());
}

void GCM::encrypt_general(Buffer& m) noexcept {
    Buffer ctr_register{diffusion_block_};
    key_encrypt_inplace(ctr_register);
    m ^= ctr_register;
    gcm_utils::inc_counter(diffusion_block_);
    payload_len_ += m.size();
};

Buffer GCM::encrypt(const Buffer& plaintext) noexcept {
    Buffer ciphertext{plaintext};
    encrypt_general(ciphertext);
    tag_.update_tag(ciphertext.block());
    return ciphertext;
}

Buffer GCM::decrypt(const Buffer& ciphertext) noexcept {
    tag_.update_tag(ciphertext.block());
    Buffer plaintext{ciphertext};
    encrypt_general(plaintext);
    return plaintext;
}

Buffer GCM::encrypt_cp(const Buffer& block) noexcept {
    Buffer buf{block};
    encrypt(buf);
    return buf;
};

Buffer GCM::tag() noexcept {
    using gcm_utils::AuthTag;

    uint128_t len_a_c{(uint128_t(aad_len_) << 64) | payload_len_};

    len_a_c ^= tag_.value();

    uint128_t tag = AuthTag::galois_multiply(len_a_c, tag_.H());
    tag ^= tag_.counter0();

    Block tag_block{};
    AuthTag::uint128_t_to_bytes(tag, tag_block);

    return {tag_block, BLOCK_SIZE};
}

namespace gcm_utils {

void inc_counter(Buffer& buffer) noexcept {
    Buffer::Bytes& block = buffer.bytes();
    for (uint8_t i = BLOCK_SIZE - 1; i >= gcm_utils::IV_SIZE; --i) {
        ++block[i];
        if (block[i] != 0) return;
    }
}

Buffer make_gcm_iv() noexcept {
    Block block{};
    fill_bytes_n(block, 12);

    // counter bytes, zero values for the last 4 bytes
    for (uint8_t i = IV_SIZE; i < BLOCK_SIZE; ++i) {
        block[i] = 0;
    }

    return Buffer{block, BLOCK_SIZE};
}

uint128_t AuthTag::bytes_to_uint128_t(const Block& bytes) {
    uint128_t result = 0;

    const uint8_t M = bytes.size();
    for (uint8_t i = 0; i < M; ++i) {
        result |= uint128_t(bytes[bytes.size() - 1 - i]) << (i * 8);
    }

    return result;
};

const uint128_t& AuthTag::H() const noexcept { return H_; };

void AuthTag::uint128_t_to_bytes(const uint128_t& n, Block& bytes) {
    const uint8_t M = bytes.size();
    uint128_t bitmask = 0xff;
    for (uint8_t i = 0; i < M; ++i) {
        bytes[i] = uint8_t((n >> ((15 - i) * 8) & 0xff));
    }
};

void AuthTag::update_tag(const Block& ciphertext) {
    const uint128_t X = AuthTag::bytes_to_uint128_t(ciphertext) ^ tag_;
    tag_ = galois_multiply(X, H_);
}

uint128_t AuthTag::galois_multiply(const uint128_t& X, const uint128_t& H) {
    // Refer to section 2.5 Multiplication in GF(2^128)
    // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
    constexpr static uint128_t R = uint128_t(0b11100001) << 120;

    uint128_t Z = 0;
    uint128_t V = X;

    uint128_t bitmask = 1;
    for (uint8_t i = 0; i < 128; ++i) {
        if (H & bitmask) {
            Z ^= V;
        }

        const bool lsb_set = (V & 1) != 0;
        V >>= 1;
        if (lsb_set) {
            V ^= R;
        }

        bitmask <<= 1;
    }

    return Z;
}

uint128_t AuthTag::value() const noexcept { return tag_; }

uint128_t AuthTag::counter0() const noexcept {
    Block ctr = counter_0_.block();
    return AuthTag::bytes_to_uint128_t(ctr);
}

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
