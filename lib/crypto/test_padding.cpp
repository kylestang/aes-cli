#include <catch2/catch_test_macros.hpp>
#include <crypto/padding.hpp>

using crypto::Block;

TEST_CASE("padding::pad_") {
    {
        Block buf{'f', 'f'};
        padding::pad_(buf, 8, 8 - 2);

        const char expected[8]{'f', 'f', 6, 6, 6, 6, 6, 6};
        for (std::size_t i = 0; i < 8; ++i) {
            REQUIRE(buf[i] == expected[i]);
        }
    }

    {
        Block buf{};
        padding::pad_(buf, 8, 8);
        for (const char& b : buf) {
            REQUIRE(b == 8);
        }
    }
}
