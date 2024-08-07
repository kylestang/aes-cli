#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto {
const std::size_t BLOCK_SIZE = 16;  // 16 bytes
using Block = std::array<uint8_t, BLOCK_SIZE>;
}  // namespace crypto
