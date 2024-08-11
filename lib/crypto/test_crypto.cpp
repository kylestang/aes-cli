#include <catch2/catch_test_macros.hpp>
#include <crypto/crypto.hpp>
#include <cstdint>

namespace crypto {

// for testing
bool operator==(const Block& left, const Block& right) {
    for (uint8_t i = 0; i < left.size(); ++i) {
        if (left[i] != right[i]) return false;
    }
    return true;
}

TEST_CASE("crypto::Buffer::pad_pkcs7") {
    SECTION("pads non-empty buffer in ctor") {
        Buffer buf{{'f', 'f'}, 2};  // it pads in constructor
        REQUIRE(buf.size() == BLOCK_SIZE);
        const Block expected{'f', 'f', 14, 14, 14, 14, 14, 14,
                             14,  14,  14, 14, 14, 14, 14, 14};
        REQUIRE(buf.block() == expected);
        REQUIRE(buf.size() == BLOCK_SIZE);
    }

    SECTION("pads empty buffer in ctor") {
        const Buffer buf{{}, 0};
        REQUIRE(buf.size() == BLOCK_SIZE);
        for (const uint8_t& b : buf.block()) {
            REQUIRE(b == BLOCK_SIZE);
        }
    }
}

TEST_CASE("crypto::Buffer::rm_pad_pkcs7") {
    Block original{'f', 'f'};
    Buffer buf{original, 2};
    Block expected{
        'f', 'f', 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    };
    REQUIRE(buf.block() == expected);
    buf.rm_pad_pkcs7();
    REQUIRE(buf.block() == original);
    REQUIRE(buf.size() == 2);
}

TEST_CASE("crypto::Buffer - xor") {
    const Buffer a{{11, 13, 10, 5, 9, 12, 13, 15, 8, 4, 9, 6, 3, 1, 3, 6},
                   BLOCK_SIZE};
    const Buffer b{{14, 5, 8, 8, 2, 5, 1, 15, 12, 0, 11, 12, 0, 0, 5, 9},
                   BLOCK_SIZE};
    const Block expected{5, 8, 2, 13, 11, 9, 12, 0, 4, 4, 2, 10, 3, 1, 6, 15};

    SECTION("operator^") {
        const Buffer result = a ^ b;
        REQUIRE(result.block() == expected);
    }

    SECTION("operator^=") {
        Buffer a_mut = a;
        a_mut ^= b;
        REQUIRE(a_mut.block() == expected);
    }
};

TEST_CASE("crypto::make_iv") {
    std::array iv1 = make_iv();
    std::array iv2 = make_iv();
    REQUIRE_FALSE(iv1 == iv2);
}

}  // namespace crypto
