#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <cstring>
#include <io/io.hpp>

TEST_CASE("io::mode_op_parser") {
    SECTION("parses correct mode of operation") {
        using io::ModeOfOperation;

        const std::pair<std::string, ModeOfOperation> test_cases[]{
            {"gcm", ModeOfOperation::GCM}, {"gcM", ModeOfOperation::GCM},
            {"gCm", ModeOfOperation::GCM}, {"gCM", ModeOfOperation::GCM},
            {"Gcm", ModeOfOperation::GCM}, {"GcM", ModeOfOperation::GCM},
            {"GCm", ModeOfOperation::GCM}, {"GCM", ModeOfOperation::GCM},

            {"ecb", ModeOfOperation::ECB}, {"ecB", ModeOfOperation::ECB},
            {"eCb", ModeOfOperation::ECB}, {"eCB", ModeOfOperation::ECB},
            {"Ecb", ModeOfOperation::ECB}, {"EcB", ModeOfOperation::ECB},
            {"ECb", ModeOfOperation::ECB}, {"ECB", ModeOfOperation::ECB},

            {"cbc", ModeOfOperation::CBC}, {"cbC", ModeOfOperation::CBC},
            {"cBc", ModeOfOperation::CBC}, {"cBC", ModeOfOperation::CBC},
            {"Cbc", ModeOfOperation::CBC}, {"CbC", ModeOfOperation::CBC},
            {"CBc", ModeOfOperation::CBC}, {"CBC", ModeOfOperation::CBC},
        };

        for (const auto& [input, output] : test_cases) {
            REQUIRE(io::mode_op_parser(input) == output);
        }
    };

    SECTION("throws invalid mode of operation errors") {
        std::string test_cases[]{
            "hello",
            "world",
            "foo",
            "bar",
        };

        for (const std::string& test : test_cases) {
            REQUIRE_THROWS_AS(io::mode_op_parser(test), io::IOError);
        }
    }
}

TEST_CASE("io::key_parser") {
    const auto default_key = [](std::size_t len) -> std::string {
        std::string key{};
        key.reserve(len);
        for (std::size_t i = 0; i < len; ++i) {
            key.push_back('a');
        }
        return key;
    };

    std::string mockenv = default_key(32);
    setenv("AES_CLI_KEY", mockenv.c_str(), 1);

    auto cmp_fn = [&mockenv](io::Key& b, std::size_t n) -> bool {
        for (std::size_t i = 0; i < n; ++i) {
            if (mockenv.at(i) != b[i]) {
                return false;
            }
        }
        return true;
    };

    SECTION("with no key") {
        const std::string key_arg = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert(key_arg.size() == 32);

        io::Key key = io::key_parser(key_arg);
        REQUIRE(cmp_fn(key, 32));
    };

    SECTION("with some key") {
        std::size_t sizes[3]{16, 24, 32};
        for (const std::size_t& size : sizes) {
            const std::string mockkey = default_key(size);
            REQUIRE_NOTHROW(io::key_parser(mockkey));
        }
    };

    SECTION("with invalid key length") {
        std::size_t sizes[]{1,   123, 51, 45,  52,  434, 236, 65,
                            432, 45,  43, 432, 532, 435, 935, 325};
        for (const std::size_t& size : sizes) {
            const std::string mockkey = default_key(size);
            REQUIRE_THROWS_AS(io::key_parser(mockkey), io::IOError);
        }
    };
};
