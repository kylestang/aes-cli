#include <array>
#include <crypto/crypto.hpp>
#include <crypto/key.hpp>
#include <crypto/tables.hpp>
#include <cstdint>
#include <io/io.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace crypto {

Block sub_bytes(const Block matrix) {
    return Block{
        sub_byte(matrix[0]),  sub_byte(matrix[1]),  sub_byte(matrix[2]),
        sub_byte(matrix[3]),  sub_byte(matrix[4]),  sub_byte(matrix[5]),
        sub_byte(matrix[6]),  sub_byte(matrix[7]),  sub_byte(matrix[8]),
        sub_byte(matrix[9]),  sub_byte(matrix[10]), sub_byte(matrix[11]),
        sub_byte(matrix[12]), sub_byte(matrix[13]), sub_byte(matrix[14]),
        sub_byte(matrix[15])};
}

Block inv_sub_bytes(const Block matrix) {
    return Block{inv_sub_byte(matrix[0]),  inv_sub_byte(matrix[1]),
                 inv_sub_byte(matrix[2]),  inv_sub_byte(matrix[3]),
                 inv_sub_byte(matrix[4]),  inv_sub_byte(matrix[5]),
                 inv_sub_byte(matrix[6]),  inv_sub_byte(matrix[7]),
                 inv_sub_byte(matrix[8]),  inv_sub_byte(matrix[9]),
                 inv_sub_byte(matrix[10]), inv_sub_byte(matrix[11]),
                 inv_sub_byte(matrix[12]), inv_sub_byte(matrix[13]),
                 inv_sub_byte(matrix[14]), inv_sub_byte(matrix[15])};
}

Block shift_rows(const Block matrix) {
    return Block{matrix[0],  matrix[5],  matrix[10], matrix[15],
                 matrix[4],  matrix[9],  matrix[14], matrix[3],
                 matrix[8],  matrix[13], matrix[2],  matrix[7],
                 matrix[12], matrix[1],  matrix[6],  matrix[11]};
}

Block inv_shift_rows(const Block matrix) {
    return Block{matrix[0],  matrix[13], matrix[10], matrix[7],
                 matrix[4],  matrix[1],  matrix[14], matrix[11],
                 matrix[8],  matrix[5],  matrix[2],  matrix[15],
                 matrix[12], matrix[9],  matrix[6],  matrix[3]};
}

Block mix_columns(const Block matrix) {
    return Block{
        // Column 0
        static_cast<uint8_t>(multiply_by_2[matrix[0]] ^
                             multiply_by_3[matrix[1]] ^ matrix[2] ^ matrix[3]),
        static_cast<uint8_t>(matrix[0] ^ multiply_by_2[matrix[1]] ^
                             multiply_by_3[matrix[2]] ^ matrix[3]),
        static_cast<uint8_t>(matrix[0] ^ matrix[1] ^ multiply_by_2[matrix[2]] ^
                             multiply_by_3[matrix[3]]),
        static_cast<uint8_t>(multiply_by_3[matrix[0]] ^ matrix[1] ^ matrix[2] ^
                             multiply_by_2[matrix[3]]),

        // Column 1
        static_cast<uint8_t>(multiply_by_2[matrix[4]] ^
                             multiply_by_3[matrix[5]] ^ matrix[6] ^ matrix[7]),
        static_cast<uint8_t>(matrix[4] ^ multiply_by_2[matrix[5]] ^
                             multiply_by_3[matrix[6]] ^ matrix[7]),
        static_cast<uint8_t>(matrix[4] ^ matrix[5] ^ multiply_by_2[matrix[6]] ^
                             multiply_by_3[matrix[7]]),
        static_cast<uint8_t>(multiply_by_3[matrix[4]] ^ matrix[5] ^ matrix[6] ^
                             multiply_by_2[matrix[7]]),

        // Column 2
        static_cast<uint8_t>(multiply_by_2[matrix[8]] ^
                             multiply_by_3[matrix[9]] ^ matrix[10] ^
                             matrix[11]),
        static_cast<uint8_t>(matrix[8] ^ multiply_by_2[matrix[9]] ^
                             multiply_by_3[matrix[10]] ^ matrix[11]),
        static_cast<uint8_t>(matrix[8] ^ matrix[9] ^ multiply_by_2[matrix[10]] ^
                             multiply_by_3[matrix[11]]),
        static_cast<uint8_t>(multiply_by_3[matrix[8]] ^ matrix[9] ^ matrix[10] ^
                             multiply_by_2[matrix[11]]),

        // Column 3
        static_cast<uint8_t>(multiply_by_2[matrix[12]] ^
                             multiply_by_3[matrix[13]] ^ matrix[14] ^
                             matrix[15]),
        static_cast<uint8_t>(matrix[12] ^ multiply_by_2[matrix[13]] ^
                             multiply_by_3[matrix[14]] ^ matrix[15]),
        static_cast<uint8_t>(matrix[12] ^ matrix[13] ^
                             multiply_by_2[matrix[14]] ^
                             multiply_by_3[matrix[15]]),
        static_cast<uint8_t>(multiply_by_3[matrix[12]] ^ matrix[13] ^
                             matrix[14] ^ multiply_by_2[matrix[15]])};
}

Block inv_mix_columns(const Block matrix) {
    return Block{// Column 0
                 static_cast<uint8_t>(
                     multiply_by_14[matrix[0]] ^ multiply_by_11[matrix[1]] ^
                     multiply_by_13[matrix[2]] ^ multiply_by_9[matrix[3]]),
                 static_cast<uint8_t>(
                     multiply_by_9[matrix[0]] ^ multiply_by_14[matrix[1]] ^
                     multiply_by_11[matrix[2]] ^ multiply_by_13[matrix[3]]),
                 static_cast<uint8_t>(
                     multiply_by_13[matrix[0]] ^ multiply_by_9[matrix[1]] ^
                     multiply_by_14[matrix[2]] ^ multiply_by_11[matrix[3]]),
                 static_cast<uint8_t>(
                     multiply_by_11[matrix[0]] ^ multiply_by_13[matrix[1]] ^
                     multiply_by_9[matrix[2]] ^ multiply_by_14[matrix[3]]),

                 // Column 1
                 static_cast<uint8_t>(
                     multiply_by_14[matrix[4]] ^ multiply_by_11[matrix[5]] ^
                     multiply_by_13[matrix[6]] ^ multiply_by_9[matrix[7]]),
                 static_cast<uint8_t>(
                     multiply_by_9[matrix[4]] ^ multiply_by_14[matrix[5]] ^
                     multiply_by_11[matrix[6]] ^ multiply_by_13[matrix[7]]),
                 static_cast<uint8_t>(
                     multiply_by_13[matrix[4]] ^ multiply_by_9[matrix[5]] ^
                     multiply_by_14[matrix[6]] ^ multiply_by_11[matrix[7]]),
                 static_cast<uint8_t>(
                     multiply_by_11[matrix[4]] ^ multiply_by_13[matrix[5]] ^
                     multiply_by_9[matrix[6]] ^ multiply_by_14[matrix[7]]),

                 // Column 2
                 static_cast<uint8_t>(
                     multiply_by_14[matrix[8]] ^ multiply_by_11[matrix[9]] ^
                     multiply_by_13[matrix[10]] ^ multiply_by_9[matrix[11]]),
                 static_cast<uint8_t>(
                     multiply_by_9[matrix[8]] ^ multiply_by_14[matrix[9]] ^
                     multiply_by_11[matrix[10]] ^ multiply_by_13[matrix[11]]),
                 static_cast<uint8_t>(
                     multiply_by_13[matrix[8]] ^ multiply_by_9[matrix[9]] ^
                     multiply_by_14[matrix[10]] ^ multiply_by_11[matrix[11]]),
                 static_cast<uint8_t>(
                     multiply_by_11[matrix[8]] ^ multiply_by_13[matrix[9]] ^
                     multiply_by_9[matrix[10]] ^ multiply_by_14[matrix[11]]),

                 // Column 2
                 static_cast<uint8_t>(
                     multiply_by_14[matrix[12]] ^ multiply_by_11[matrix[13]] ^
                     multiply_by_13[matrix[14]] ^ multiply_by_9[matrix[15]]),
                 static_cast<uint8_t>(
                     multiply_by_9[matrix[12]] ^ multiply_by_14[matrix[13]] ^
                     multiply_by_11[matrix[14]] ^ multiply_by_13[matrix[15]]),
                 static_cast<uint8_t>(
                     multiply_by_13[matrix[12]] ^ multiply_by_9[matrix[13]] ^
                     multiply_by_14[matrix[14]] ^ multiply_by_11[matrix[15]]),
                 static_cast<uint8_t>(
                     multiply_by_11[matrix[12]] ^ multiply_by_13[matrix[13]] ^
                     multiply_by_9[matrix[14]] ^ multiply_by_14[matrix[15]])};
}

Block add_round_key(Block block, AesKey aes_key, size_t round) {
    std::vector<uint8_t> key = aes_key.get_key();
    return Block{
        static_cast<uint8_t>(block[0] ^ key[BLOCK_SIZE * round]),
        static_cast<uint8_t>(block[1] ^ key[BLOCK_SIZE * round + 1]),
        static_cast<uint8_t>(block[2] ^ key[BLOCK_SIZE * round + 2]),
        static_cast<uint8_t>(block[3] ^ key[BLOCK_SIZE * round + 3]),
        static_cast<uint8_t>(block[4] ^ key[BLOCK_SIZE * round + 4]),
        static_cast<uint8_t>(block[5] ^ key[BLOCK_SIZE * round + 5]),
        static_cast<uint8_t>(block[6] ^ key[BLOCK_SIZE * round + 6]),
        static_cast<uint8_t>(block[7] ^ key[BLOCK_SIZE * round + 7]),
        static_cast<uint8_t>(block[8] ^ key[BLOCK_SIZE * round + 8]),
        static_cast<uint8_t>(block[9] ^ key[BLOCK_SIZE * round + 9]),
        static_cast<uint8_t>(block[10] ^ key[BLOCK_SIZE * round + 10]),
        static_cast<uint8_t>(block[11] ^ key[BLOCK_SIZE * round + 11]),
        static_cast<uint8_t>(block[12] ^ key[BLOCK_SIZE * round + 12]),
        static_cast<uint8_t>(block[13] ^ key[BLOCK_SIZE * round + 13]),
        static_cast<uint8_t>(block[14] ^ key[BLOCK_SIZE * round + 14]),
        static_cast<uint8_t>(block[15] ^ key[BLOCK_SIZE * round + 15])};
}

std::string print_block(Block& block) {
    std::ostringstream result;
    for (int i = 0; i < block.size(); i++) {
        result << std::setfill('0') << std::setw(2) << std::hex << (int)block[i]
               << " ";
    }
    result << "\n";
    return result.str();
}

Block encrypt(Block block, AesKey key) {
    // Initial round_key
    block = add_round_key(block, key, 0);

    // Rounds
    for (size_t round = 1; round < key.get_rounds(); round++) {
        io::Writer::dbg(std::cout, std::format("Encrypt input to round {}: {}",
                                               round, print_block(block)));

        block = sub_bytes(block);
        io::Writer::dbg(std::cout,
                        std::format("Sub result: {}", print_block(block)));

        block = shift_rows(block);
        io::Writer::dbg(std::cout,
                        std::format("Shift result: {}", print_block(block)));

        block = mix_columns(block);
        io::Writer::dbg(std::cout,
                        std::format("Mix result: {}", print_block(block)));

        block = add_round_key(block, key, round);
    }

    // Final round
    block = sub_bytes(block);
    block = shift_rows(block);
    block = add_round_key(block, key, key.get_rounds());

    return block;
}

Block decrypt(Block block, AesKey key) {
    // Initial round_key
    block = add_round_key(block, key, key.get_rounds());

    // Rounds
    for (size_t round = key.get_rounds() - 1; round > 0; round--) {
        io::Writer::dbg(std::cout, std::format("Decrypt input to round {}: {}",
                                               round, print_block(block)));

        block = inv_shift_rows(block);
        io::Writer::dbg(std::cout,
                        std::format("Shift result: {}", print_block(block)));

        block = inv_sub_bytes(block);
        io::Writer::dbg(std::cout,
                        std::format("Sub result: {}", print_block(block)));

        block = add_round_key(block, key, round);

        block = inv_mix_columns(block);
        io::Writer::dbg(std::cout,
                        std::format("Mix result: {}", print_block(block)));
    }

    // Final round
    block = inv_shift_rows(block);
    block = inv_sub_bytes(block);
    block = add_round_key(block, key, 0);

    return block;
}

}  // namespace crypto
