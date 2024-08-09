#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto {

// Cipher block, 128 bits (16 bytes)
inline const std::size_t BLOCK_SIZE = 16;
using Block = std::array<uint8_t, BLOCK_SIZE>;

struct Buffer {
    private:
        Block buf_;
        std::size_t size_;

    public:
        Buffer();
        Buffer(Block block, std::size_t n);
        Buffer(const Buffer&) = default;

        Buffer& operator^=(const Buffer& other) noexcept;
        Buffer operator^(const Buffer& other) const noexcept;

        Block& block() noexcept;
        const Block& block() const noexcept;
        std::size_t size() const noexcept;

        // add padding for a 128 bit block `buf_`,
        // with currently `size_` size
        void pad_pkcs7() noexcept;
        void rm_pad_pkcs7() noexcept;
};

// Initial vector, 96 bits (12 bytes)
inline const std::size_t IV_SIZE = 12;
using IV = std::array<uint8_t, IV_SIZE>;

namespace gcmutils {

// since the nonce is 96 bits (12 bytes), the counter potion is only
// the last 4 bytes. Increment this counter value byte by byte, then wrap
// when the 4th last bit goes from 255 -> 0
void block_inc(Block& block) noexcept;

}  // namespace gcmutils

}  // namespace crypto
