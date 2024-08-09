#include <catch2/catch_test_macros.hpp>
#include <crypto/ciphermode.hpp>
#include <cstdint>

namespace crypto::ciphermode {

TEST_CASE("gcm_utils::inc_counter") {
    SECTION("bit cascades") {
        Block buf{};
        buf[15] = 255;
        buf[14] = 255;
        buf[13] = 255;
        buf[12] = 0;
        gcm_utils::inc_counter(buf);

        REQUIRE(buf[12] == 1);
        for (uint8_t i = IV_SIZE + 1; i < BLOCK_SIZE; ++i) {
            REQUIRE(buf[i] == 0);
        }
    }

    SECTION("bit wrapped") {
        Block buf{};
        buf[15] = 255;
        buf[14] = 255;
        buf[13] = 255;
        buf[12] = 255;
        gcm_utils::inc_counter(buf);

        for (uint8_t i = IV_SIZE; i < BLOCK_SIZE; ++i) {
            REQUIRE(buf[i] == 0);
        }
    }
}

TEST_CASE("gcm_utils::make_gcm_iv") {
    Block buf = gcm_utils::make_gcm_iv();

    // last 4 bytes initialized to 0, these are the `counter` bytes.
    uint8_t counter = 0;
    for (uint8_t i = IV_SIZE; i < BLOCK_SIZE; ++i) {
        REQUIRE(buf[i] == 0);
    }

    bool random_valid = false;
    for (uint8_t i = 0; i < IV_SIZE; ++i) {
        if (buf[i] != 0) random_valid = true;
    }
    REQUIRE(random_valid);

    SECTION("iv's are random") {
    Block buf2 = gcm_utils::make_gcm_iv();
    bool eq = true;
    for (uint8_t i = 0; i < BLOCK_SIZE; ++i) {
        if (buf[i] != buf2[i]) {
            eq = false;
        }
    }
    REQUIRE_FALSE(eq);
    }
}

}  // namespace crypto::ciphermode
