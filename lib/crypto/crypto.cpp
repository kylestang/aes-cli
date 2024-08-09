#include <crypto/crypto.hpp>

namespace crypto {

Buffer::Buffer() : buf_{Block{}}, size_{0} {
    pad_pkcs7();
}

Buffer::Buffer(Block block, std::size_t n) : buf_{block}, size_{n} {
    pad_pkcs7();
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

Block& Buffer::block() noexcept { return buf_; }
const Block& Buffer::block() const noexcept { return buf_; }

std::size_t Buffer::size() const noexcept { return size_; }

void Buffer::pad_pkcs7() noexcept {
    const uint8_t pad_size = BLOCK_SIZE - size_;
    for (std::size_t i = 0; i < pad_size; ++i) {
        buf_[BLOCK_SIZE - 1 - i] = pad_size;
    }
    size_ = BLOCK_SIZE;
}

void Buffer::rm_pad_pkcs7() noexcept {
    const uint8_t pad_size = buf_[size_ - 1];

    if (pad_size > BLOCK_SIZE) return;  // no padding
    size_ = BLOCK_SIZE - pad_size;
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
