#include <boost/multiprecision/cpp_int.hpp>
#include <catch2/catch_test_macros.hpp>
#include <crypto/ciphermode.hpp>
#include <cstdint>

namespace crypto::ciphermode {

TEST_CASE("gcm_utils::inc_counter") {
    /*
    const Block data{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255},
                      BLOCK_SIZE};
    SECTION("bit cascades") {
        Block buf{data};
        gcm_utils::inc_counter(buf);

        REQUIRE(buf.block()[12] == 1);
        for (uint8_t i = IV_SIZE + 1; i < BLOCK_SIZE; ++i) {
            REQUIRE(buf.block()[i] == 0);
        }
    }

    SECTION("bit wrapped") {
        Block buf{data};
        buf[12] = 255;
        gcm_utils::inc_counter(buf);

        for (uint8_t i = IV_SIZE; i < BLOCK_SIZE; ++i) {
            REQUIRE(buf.at(i) == 0);
        }
    }
*/
}

namespace gcm_utils {

TEST_CASE("AuthTag::bytes_to_uint128_t and AuthTag::uint128_t_to_bytes") {
    using boost::multiprecision::uint128_t;

    {
        const Block bytes{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255};
        const uint128_t result = AuthTag::bytes_to_uint128_t(bytes);
        REQUIRE(result == uint128_t(255));
    }

    {
        const Block bytes{0,   0,   0,   0,   0,   0,   0,   0,
                          255, 255, 255, 255, 255, 255, 255, 255};
        const uint128_t result = AuthTag::bytes_to_uint128_t(bytes);
        REQUIRE(result == uint128_t(0xffffffffffffffff));
    }

    {
        const Block bytes{0,   0,   0,   0,   0,   0,   0,   0,
                          255, 255, 255, 255, 255, 255, 255, 255};
        const uint128_t result = AuthTag::bytes_to_uint128_t(bytes);
        Block conv_result{};
        AuthTag::uint128_t_to_bytes(result, conv_result);

        REQUIRE(bytes == conv_result);
    }
}

}  // namespace gcm_utils

}  // namespace crypto::ciphermode
