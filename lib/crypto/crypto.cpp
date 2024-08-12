#include <algorithm>
#include <cassert>
#include <crypto/crypto.hpp>

namespace crypto {

Block& operator^=(Block& l, const Block& r) {
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        l.at(i) ^= r.at(i);
    }
    return l;
}

Block operator^(const Block& l, const Block& r) {
    Block ll{l};
    ll ^= r;
    return ll;
}

Buffer::Buffer(Block block, std::size_t n) : Buffer::Bytes(n) {
    reserve(BLOCK_SIZE);
    resize(n);
    std::copy_n(block.begin(), n, begin());
}

Buffer& Buffer::operator^=(const Buffer& other) noexcept {
    assert(size() == other.size());
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        at(i) ^= other.at(i);
    }
    return *this;
}

Buffer Buffer::operator^(const Buffer& other) const noexcept {
    assert(size() == other.size());
    Buffer tmp{*this};
    tmp ^= other;
    return tmp;
}

Block Buffer::block() const noexcept {
    Block b{};
    std::copy(begin(), end(), b.begin());
    return b;
}

Buffer::Bytes& Buffer::bytes() noexcept { return *this; }
const Buffer::Bytes& Buffer::bytes() const noexcept { return *this; }

void Buffer::pad_pkcs7() noexcept {
    const uint8_t pad_size = BLOCK_SIZE - size();
    resize(BLOCK_SIZE);
    for (std::size_t i = 0; i < pad_size; ++i) {
        at(BLOCK_SIZE - 1 - i) = pad_size;
    }
}

void Buffer::rm_pad_pkcs7() noexcept {
    const uint8_t pad_size = at(size() - 1);

    if (pad_size > BLOCK_SIZE) return;  // no padding

    // valid padding?
    for (uint8_t i = 0; i < pad_size; ++i) {
        if (at(BLOCK_SIZE - 1 - i) != pad_size) return;
    }

    for (uint8_t i = 0; i < pad_size; ++i) {
        pop_back();
    }

    shrink_to_fit();
}

void block_inc(Block& block) noexcept {
    for (uint8_t i = 15; i >= 12; --i) {
        ++block[i];
        if (block[i] != 0) return;
    }
}

}  // namespace crypto
