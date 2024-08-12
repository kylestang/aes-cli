#include <catch2/catch_test_macros.hpp>
#include <crypto/crypto.hpp>
#include <cstdint>

namespace crypto {

// for testing
bool operator==(const Buffer& left, const Block& right) {
    if (left.size() != right.size()) return false;
    const Block block = left.block();
    return block == right;
}

// for testing
bool operator==(const Buffer& left, const Buffer& right) {
    return left.bytes() == right.bytes();
}

TEST_CASE("crypto::Buffer::pad_pkcs7") {
    SECTION("non-empty buffer") {
        Buffer buf{{'f', 'f'}, 2};
        buf.pad_pkcs7();
        REQUIRE(buf.size() == BLOCK_SIZE);
        const Block expected{'f', 'f', 14, 14, 14, 14, 14, 14,
                             14,  14,  14, 14, 14, 14, 14, 14};
        REQUIRE(buf == expected);
    }

    SECTION("empty buffer") {
        Buffer buf{{}, 0};
        buf.pad_pkcs7();
        REQUIRE(buf.size() == BLOCK_SIZE);
        for (const uint8_t& b : buf.block()) {
            REQUIRE(b == BLOCK_SIZE);
        }
    }
}

TEST_CASE("crypto::Buffer::rm_pad_pkcs7") {
    SECTION("removes padding properly") {
        Buffer buf{{'f', 'f'}, 2};
        const Buffer expected{buf};

        buf.pad_pkcs7();
        REQUIRE(buf != expected);
        REQUIRE(buf.size() == BLOCK_SIZE);
        buf.rm_pad_pkcs7();

        REQUIRE(buf == expected);
        REQUIRE(buf.size() == 2);
    }

    SECTION("does not modify with invalid padding") {
        const Block data{
            255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 12,  2,   3,   3,
        };

        const Buffer expected{data, BLOCK_SIZE};
        Buffer buf{expected};

        buf.rm_pad_pkcs7();
        REQUIRE(buf == expected);
    };
};

TEST_CASE("crypto::Buffer - xor") {
    const Buffer a{{11, 13, 10, 5, 9, 12, 13, 15, 8, 4, 9, 6, 3, 1, 3, 6},
                   BLOCK_SIZE};
    const Buffer b{{14, 5, 8, 8, 2, 5, 1, 15, 12, 0, 11, 12, 0, 0, 5, 9},
                   BLOCK_SIZE};
    const Block expected{5, 8, 2, 13, 11, 9, 12, 0, 4, 4, 2, 10, 3, 1, 6, 15};

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

TEST_CASE("crypto::fill_bytes_n") {
    Buffer iv1{};
    iv1.resize(IV_SIZE);
    Buffer iv2{};
    iv2.resize(IV_SIZE);

    fill_bytes_n(iv1, IV_SIZE);
    fill_bytes_n(iv2, IV_SIZE);

    REQUIRE_FALSE(iv1 == iv2);

    for (uint8_t i = IV_SIZE; i < BLOCK_SIZE; ++i) {
        REQUIRE(iv1.at(i) == 0);
        REQUIRE(iv2.at(i) == 0);
    }

    SECTION("it throws") {
        Buffer buf{};
        buf.resize(BLOCK_SIZE);
        REQUIRE_THROWS_AS(fill_bytes_n(buf, BLOCK_SIZE + 1), std::logic_error);
    }
};

}  // namespace crypto
