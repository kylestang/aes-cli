#include <catch2/catch_test_macros.hpp>
#include <crypto/crypto.cpp>

namespace crypto {

TEST_CASE("crypto::Block - xor") {
    const Block a = {11, 13, 10, 5, 9, 12, 13, 15, 8, 4, 9, 6, 3, 1, 3, 6};
    const Block b = {14, 5, 8, 8, 2, 5, 1, 15, 12, 0, 11, 12, 0, 0, 5, 9};
    const Block expected = {5, 8, 2, 13, 11, 9, 12, 0,
                            4, 4, 2, 10, 3,  1, 6,  15};

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

TEST_CASE("be_bytes_to_uint64") {
    Block buf{};
    uint64_to_be_bytes(12, buf);
    REQUIRE(buf[15] == 12);
}

}  // namespace crypto
