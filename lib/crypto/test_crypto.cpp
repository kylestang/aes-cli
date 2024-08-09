#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <crypto/crypto.hpp>
#include <cstddef>
#include <cstdint>

namespace crypto {

TEST_CASE("crypto::Buffer::pad_pkcs7") {
    {
        Buffer buf{{'f', 'f'}, 2};
        buf.pad_pkcs7();

        const Block expected{'f', 'f', 14, 14, 14, 14, 14, 14,
                             14,  14,  14, 14, 14, 14, 14, 14};
        for (std::size_t i = 0; i < 8; ++i) {
            REQUIRE(buf.block()[i] == expected[i]);
        }
    }

    {
        Buffer buf{{}, 0};
        buf.pad_pkcs7();

        Block expected{};
        std::fill(expected.begin(), expected.end(), BLOCK_SIZE);
        for (const uint8_t& b : buf.block()) {
            REQUIRE(b == BLOCK_SIZE);
        }
    }
}

// for testing
bool operator==(const Buffer& left, const Buffer& right) {
    if (left.size() != right.size()) return false;
    for (uint8_t i = 0; i < left.size(); ++i) {
        if (left.block()[i] != right.block()[i]) return false;
    }
    return true;
}

TEST_CASE("crypto::Block - xor") {
    const Buffer a{{11, 13, 10, 5, 9, 12, 13, 15, 8, 4, 9, 6, 3, 1, 3, 6},
                   BLOCK_SIZE};
    const Buffer b{{14, 5, 8, 8, 2, 5, 1, 15, 12, 0, 11, 12, 0, 0, 5, 9},
                   BLOCK_SIZE};
    const Buffer expected{{5, 8, 2, 13, 11, 9, 12, 0, 4, 4, 2, 10, 3, 1, 6, 15},
                          BLOCK_SIZE};

    SECTION("operator^") {
        const Buffer result = a ^ b;
        REQUIRE(result == expected);
    }

    SECTION("operator^=") {
        Buffer a_mut = a;
        a_mut ^= b;
        REQUIRE(a_mut == expected);
    }
};

}  // namespace crypto
