#include <boost/multiprecision/cpp_int.hpp>
#include <crypto/aes.hpp>
#include <crypto/ciphermode.hpp>
#include <cstdint>

namespace crypto::ciphermode {

// CipherMode abstract class
CipherMode::CipherMode(AES& key, Buffer iv)
    : key_{key}, diffusion_block_{iv} {};

void CipherMode::key_encrypt_inplace(Buffer& block) noexcept {
    Block arr;
    std::copy(block.begin(), block.end(), arr.begin());
    Block result = crypto::encrypt(arr, key_);
    std::copy(result.begin(), result.end(), block.begin());
}

void CipherMode::key_decrypt_inplace(Buffer& block) noexcept {
    Block arr;
    std::copy(block.begin(), block.end(), arr.begin());
    Block result = crypto::decrypt(arr, key_);
    std::copy(result.begin(), result.end(), block.begin());
}

void encrypt_fd(std::istream&, std::ostream&) noexcept {

};

void decrypt_fd(std::istream&, std::ostream&) noexcept {

};

// ECB
ECB::ECB(AES& key) : CipherMode{key, Buffer{}} {}

void ECB::encrypt(Buffer& buf) noexcept { key_encrypt_inplace(buf); }

void ECB::decrypt(Buffer& buf) noexcept { key_decrypt_inplace(buf); }

// CBC
CBC::CBC(AES& key, Buffer iv) : CipherMode{key, iv} {}

void CBC::encrypt(Buffer& buf) noexcept {
    buf ^= diffusion_block_;
    key_encrypt_inplace(buf);
    diffusion_block_ = buf;
}

void CBC::decrypt(Buffer& buf) noexcept {
    Buffer ciphertext{buf};
    key_decrypt_inplace(buf);
    buf ^= diffusion_block_;
    diffusion_block_ = ciphertext;
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

void GCM::encrypt(Buffer& buf) noexcept {
    encrypt_general(buf);
    tag_.update_tag(buf.block());
}

void GCM::decrypt(Buffer& buf) noexcept {
    tag_.update_tag(buf.block());
    encrypt_general(buf);
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
