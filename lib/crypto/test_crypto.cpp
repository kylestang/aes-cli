#include <catch2/catch_test_macros.hpp>
#include <crypto/crypto.hpp>
#include <cstdint>

namespace crypto {

TEST_CASE("crypto::pad_pkcs7") {
    SECTION("non-empty block") {
        Block buf{'f', 'f'};
        pad_pkcs7(buf, 2);
        REQUIRE(buf.size() == BLOCK_SIZE);
        const Block expected{'f', 'f', 14, 14, 14, 14, 14, 14,
                             14,  14,  14, 14, 14, 14, 14, 14};
        REQUIRE(buf == expected);
    }

    SECTION("empty buffer") {
        Block buf{};
        pad_pkcs7(buf, 0);
        REQUIRE(buf.size() == BLOCK_SIZE);
        for (const uint8_t& b : buf) {
            REQUIRE(b == BLOCK_SIZE);
        }
    }
}

TEST_CASE("crypto::rm_pad_pkcs7") {
    SECTION("removes padding properly") {
        Block buf{'f', 'f'};
        const Block expected{'f', 'f'};
        pad_pkcs7(buf, 2);
        REQUIRE(buf != expected);
        std::size_t bytes_remain = rm_pad_pkcs7(buf);
        REQUIRE(buf == expected);
        REQUIRE(bytes_remain == 2);
    }

    SECTION("does not modify with invalid padding") {
        const Block data{
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 12,  2,   3,   3,
        };

        const Block expected{data};
        Block buf{expected};

        REQUIRE(rm_pad_pkcs7(buf) == BLOCK_SIZE);
        REQUIRE(buf == expected);
    };
};

TEST_CASE("crypto::Block - xor") {
    const Block a{11, 13, 10, 5, 9, 12, 13, 15, 8, 4, 9, 6, 3, 1, 3, 6};
    const Block b{14, 5, 8, 8, 2, 5, 1, 15, 12, 0, 11, 12, 0, 0, 5, 9};
    const Block expected{5, 8, 2, 13, 11, 9, 12, 0, 4, 4, 2, 10, 3, 1, 6, 15};

    SECTION("operator^") {
        const Block result = a ^ b;
        REQUIRE(result == expected);
    }

    SECTION("operator^=") {
        Block a_mut = a;
        a_mut ^= b;
        REQUIRE(a_mut == expected);
    }
};

TEST_CASE("crypto::fill_bytes_n") {
    Block iv1{};
    Block iv2{};

    fill_bytes_n(iv1, IV_SIZE);
    fill_bytes_n(iv2, IV_SIZE);

    REQUIRE_FALSE(iv1 == iv2);

    for (uint8_t i = IV_SIZE; i < BLOCK_SIZE; ++i) {
        REQUIRE(iv1.at(i) == 0);
        REQUIRE(iv2.at(i) == 0);
    }

    SECTION("it throws") {
        Block buf{};
        REQUIRE_THROWS_AS(fill_bytes_n(buf, BLOCK_SIZE + 1), std::logic_error);
    }
};

}  // namespace crypto
