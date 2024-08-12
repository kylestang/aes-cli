#include <algorithm>
#include <boost/multiprecision/cpp_int.hpp>
#include <crypto/aes.hpp>
#include <crypto/ciphermode.hpp>
#include <cstdint>
#include <io/io.hpp>

#include "crypto.hpp"
#include "crypto/key.hpp"
#include "errors/errors.hpp"

namespace crypto::ciphermode {

// CipherMode abstract class
CipherMode::CipherMode(AES& key, std::istream& in, std::ostream& out, Block& iv)
    : key_{key}, input_fd_{in}, output_fd_{out}, diffusion_block_{iv} {}

void CipherMode::key_encrypt_inplace(Block& arr) noexcept {
    Block result = crypto::encrypt(arr, key_);
    std::copy(result.begin(), result.end(), arr.begin());
}

void CipherMode::key_decrypt_inplace(Block& block) noexcept {
    Block result = crypto::decrypt(block, key_);
    std::copy(result.begin(), result.end(), block.begin());
}

void CipherMode::encrypt_fd() noexcept {
    Block buf{};

    std::size_t bytes_read =
        input_fd_.readsome(reinterpret_cast<char*>(buf.data()), BLOCK_SIZE);

    while (true) {
        if (input_fd_.peek() <= 0) {  // last block
            break;
        }

        encrypt(buf);
        output_fd_ << buf.data();

        bytes_read =
            input_fd_.readsome(reinterpret_cast<char*>(buf.data()), BLOCK_SIZE);
    }

    pad_pkcs7(buf, bytes_read);
    encrypt(buf);
    io::Writer::write_block(output_fd_, buf, BLOCK_SIZE);

    std::vector<char> t = tag();
    output_fd_ << t.data();
};

void CipherMode::decrypt_fd() {
    Block buf{};
    Block cache{};

    std::size_t bytes_read =
        input_fd_.readsome((char*)(cache.data()), BLOCK_SIZE);

    while (true) {
        if (input_fd_.peek() <= 0) {  // last block
            break;
        }

        bytes_read = input_fd_.readsome((char*)buf.data(), BLOCK_SIZE);
        decrypt(cache);
        io::Writer::write_block(output_fd_, cache, BLOCK_SIZE);
        cache = buf;
    }

    decrypt(cache);
    std::size_t bytes_remained = rm_pad_pkcs7(cache);
    io::Writer::write_block(output_fd_, cache, bytes_remained);

    // validate tag
    std::vector<char> t = tag();
    std::cout << t.size() << std::endl;
    if (t.size() == 0) {
        return;
    }
    Block tt{};
    std::copy(t.begin(), t.end(), tt.begin());

    using gcm_utils::AuthTag;

    const bool tag_valid =
        AuthTag::bytes_to_uint128_t(tt) == AuthTag::bytes_to_uint128_t(buf);
    if (!tag_valid) {
        throw io::IOError{"data integrity violated", errors::Error::Other};
    }
};

// ECB
ECB::ECB(AES& key, std::istream& in, std::ostream& out, Block& iv)
    : CipherMode{key, in, out, iv} {};

void ECB::encrypt(Block& buf) noexcept { key_encrypt_inplace(buf); }

void ECB::decrypt(Block& buf) noexcept { key_decrypt_inplace(buf); }

// CBC
CBC::CBC(AES& key, std::istream& in, std::ostream& out, Block& iv)
    : CipherMode{key, in, out, iv} {};

void CBC::encrypt(Block& buf) noexcept {
    buf ^= diffusion_block_;
    key_encrypt_inplace(buf);
    diffusion_block_ = buf;
}

void CBC::decrypt(Block& buf) noexcept {
    Block ciphertext{buf};
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
GCM::GCM(AES& key, std::istream& in, std::ostream& out, Block& iv)
    : CipherMode{key, in, out, iv}, tag_{encrypt_cp(Block{}), encrypt_cp(iv)} {
    // the actual message starts with counter value 1
    gcm_utils::inc_counter(diffusion_block_);
    tag_.update_tag(Block{});
};

void GCM::encrypt_general(Block& m) noexcept {
    Block ctr_register{diffusion_block_};
    key_encrypt_inplace(ctr_register);
    m ^= ctr_register;
    gcm_utils::inc_counter(diffusion_block_);
    payload_len_ += m.size();
};

void GCM::encrypt(Block& buf) noexcept {
    encrypt_general(buf);
    tag_.update_tag(buf);
}

void GCM::decrypt(Block& buf) noexcept {
    tag_.update_tag(buf);
    encrypt_general(buf);
}

Block GCM::encrypt_cp(const Block& block) noexcept {
    Block buf{block};
    encrypt(buf);
    return buf;
};

std::vector<char> GCM::tag() noexcept {
    using gcm_utils::AuthTag;

    uint128_t len_a_c{(uint128_t(aad_len_) << 64) | payload_len_};

    len_a_c ^= tag_.value();

    uint128_t tag = AuthTag::galois_multiply(len_a_c, tag_.H());
    tag ^= tag_.counter0();

    Block tag_block{};
    AuthTag::uint128_t_to_bytes(tag, tag_block);

    std::vector<char> tag_out{};
    for (const auto b : tag_block) {
        tag_out.push_back(b);
    }

    return tag_out;
}

namespace gcm_utils {

void inc_counter(Block& block) noexcept {
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
    return AuthTag::bytes_to_uint128_t(counter_0_);
}

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
