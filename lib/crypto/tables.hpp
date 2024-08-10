
#include <array>
#include <cstdint>

namespace crypto {

extern std::array<std::array<uint8_t, 16>, 16> s_box;
uint8_t sub_byte(uint8_t input);
extern std::array<uint8_t, 256> multiply_by_2;
extern std::array<uint8_t, 256> multiply_by_3;
extern std::array<uint8_t, 11> round_constants;
}  // namespace crypto
