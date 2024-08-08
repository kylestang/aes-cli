#include "key.hpp"
#include "tables.hpp"
#include <array>
#include <cstdint>

namespace aes {

uint8_t substitution(uint8_t input) {
    uint8_t x = input >> 4;
    uint8_t y = input & 0xf;

    return s_box[x][y];
}

std::array<uint8_t, 16> shift_rows(const std::array<uint8_t, 16> matrix) {
    return std::array<uint8_t, 16>{
        matrix[0],  matrix[1],  matrix[2],  matrix[3],  matrix[5], matrix[6],
        matrix[7],  matrix[4],  matrix[10], matrix[11], matrix[8], matrix[9],
        matrix[15], matrix[12], matrix[13], matrix[14]};
}

std::array<uint8_t, 16> mix_columns(const std::array<uint8_t, 16> matrix) {
    return std::array<uint8_t, 16>{
        // Row 0
        static_cast<uint8_t>(multiply_by_2[matrix[0]] ^
                             multiply_by_3[matrix[4]] ^ matrix[8] ^ matrix[12]),
        static_cast<uint8_t>(multiply_by_2[matrix[1]] ^
                             multiply_by_3[matrix[5]] ^ matrix[9] ^ matrix[13]),
        static_cast<uint8_t>(multiply_by_2[matrix[2]] ^
                             multiply_by_3[matrix[6]] ^ matrix[10] ^
                             matrix[14]),
        static_cast<uint8_t>(multiply_by_2[matrix[3]] ^
                             multiply_by_3[matrix[7]] ^ matrix[11] ^
                             matrix[15]),
        // Row 1
        static_cast<uint8_t>(matrix[0] ^ multiply_by_2[matrix[4]] ^
                             multiply_by_3[matrix[8]] ^ matrix[12]),
        static_cast<uint8_t>(matrix[1] ^ multiply_by_2[matrix[5]] ^
                             multiply_by_3[matrix[9]] ^ matrix[13]),
        static_cast<uint8_t>(matrix[2] ^ multiply_by_2[matrix[6]] ^
                             multiply_by_3[matrix[10]] ^ matrix[14]),
        static_cast<uint8_t>(matrix[0] ^ multiply_by_2[matrix[4]] ^
                             multiply_by_3[matrix[8]] ^ matrix[12]),
        // Row 2
        static_cast<uint8_t>(matrix[0] ^ matrix[4] ^ multiply_by_2[matrix[8]] ^
                             multiply_by_3[matrix[12]]),
        static_cast<uint8_t>(matrix[1] ^ matrix[5] ^ multiply_by_2[matrix[9]] ^
                             multiply_by_3[matrix[13]]),
        static_cast<uint8_t>(matrix[2] ^ matrix[6] ^ multiply_by_2[matrix[10]] ^
                             multiply_by_3[matrix[14]]),
        static_cast<uint8_t>(matrix[3] ^ matrix[7] ^ multiply_by_2[matrix[11]] ^
                             multiply_by_3[matrix[15]]),
        // Row 3
        static_cast<uint8_t>(multiply_by_3[matrix[0]] ^ matrix[4] ^ matrix[8] ^
                             multiply_by_2[matrix[12]]),
        static_cast<uint8_t>(multiply_by_3[matrix[1]] ^ matrix[5] ^ matrix[9] ^
                             multiply_by_2[matrix[13]]),
        static_cast<uint8_t>(multiply_by_3[matrix[2]] ^ matrix[6] ^ matrix[10] ^
                             multiply_by_2[matrix[14]]),
        static_cast<uint8_t>(multiply_by_3[matrix[3]] ^ matrix[7] ^ matrix[11] ^
                             multiply_by_2[matrix[15]])};
}

} // namespace aes
