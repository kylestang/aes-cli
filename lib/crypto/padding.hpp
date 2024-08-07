#include <crypto/crypto.cpp>
#include <cstddef>

namespace padding {

inline void pad_(crypto::Block& buf, std::size_t full_block_size,
                 std::size_t pad_size) {
    for (std::size_t i = 0; i < pad_size; ++i) {
        buf[full_block_size - 1 - i] = pad_size;
    }
};

// add padding for a 128 bit block `buf`
inline void pad_block(crypto::Block& buf) {
    pad_(buf, crypto::BLOCK_SIZE, crypto::BLOCK_SIZE - buf.size());
}

}  // namespace padding
