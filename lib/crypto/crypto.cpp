#include <algorithm>
#include <cassert>
#include <crypto/crypto.hpp>

namespace crypto {

Buffer::Buffer(Block block, std::size_t n) {
    buf_ = Buffer::Bytes(n);
    buf_.reserve(BLOCK_SIZE);
    std::copy(block.begin(), block.end(), buf_.begin());
    assert(buf_.size() == n);
}

Buffer& Buffer::operator^=(const Buffer& other) noexcept {
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        buf_[i] ^= other.buf_[i];
    }
    return *this;
}

Buffer Buffer::operator^(const Buffer& other) const noexcept {
    Buffer tmp{*this};
    tmp ^= other;
    return tmp;
}

Block Buffer::block() const noexcept {
    Block b{};
    std::copy(buf_.begin(), buf_.end(), b.begin());
    return b;
}

Buffer::Bytes& Buffer::bytes() noexcept { return buf_; }
const Buffer::Bytes& Buffer::bytes() const noexcept { return buf_; }

std::size_t Buffer::size() const noexcept { return buf_.size(); }

void Buffer::pad_pkcs7() noexcept {
    const uint8_t pad_size = BLOCK_SIZE - size();
    for (std::size_t i = 0; i < pad_size; ++i) {
        buf_[BLOCK_SIZE - 1 - i] = pad_size;
    }
}

void Buffer::rm_pad_pkcs7() noexcept {
    const uint8_t pad_size = buf_[size() - 1];

    if (pad_size > BLOCK_SIZE) return;  // no padding

    // valid padding?
    for (uint8_t i = 0; i < pad_size; ++i) {
        if (buf_[BLOCK_SIZE - 1 - i] != pad_size) return;
    }

    for (uint8_t i = 0; i < pad_size; ++i) {
        buf_[BLOCK_SIZE - 1 - i] = 0;
    }
}

void block_inc(Block& block) noexcept {
    for (uint8_t i = 15; i >= 12; --i) {
        ++block[i];
        if (block[i] != 0) return;
    }
}

}  // namespace crypto
