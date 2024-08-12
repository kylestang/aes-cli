#include <catch2/catch_test_macros.hpp>
#include <crypto/aes.hpp>
#include <crypto/crypto.hpp>
#include <iostream>

using namespace crypto;

TEST_CASE("Substitute bytes") {
    const Block input{
        0x01, 0xde, 0x45, 0x91, 0x88, 0xaa, 0x20, 0xfe,
        0x0f, 0x0a, 0x6b, 0x3d, 0xd3, 0x50, 0x00, 0xff,
    };

    const Block expected{
        0x7c, 0x1d, 0x6e, 0x81, 0xc4, 0xac, 0xb7, 0xbb,
        0x76, 0x67, 0x7f, 0x27, 0x66, 0x53, 0x63, 0x16,
    };

    const Block result = sub_bytes(input);

    REQUIRE(expected == result);
}

TEST_CASE("Shift rows") {
    const Block input{
        0xca, 0xf3, 0x87, 0x9e, 0x4e, 0x68, 0xb6, 0xc3,
        0xd5, 0x6e, 0xda, 0xa8, 0x30, 0x8c, 0x5a, 0x37,
    };

    const Block expected{
        0xca, 0x68, 0xda, 0x37, 0x4e, 0x6e, 0x5a, 0x9e,
        0xd5, 0x8c, 0x87, 0xc3, 0x30, 0xf3, 0xb6, 0xa8,

    };

    const Block result = shift_rows(input);

    REQUIRE(expected == result);
}

TEST_CASE("Mix columns") {
    const Block input{
        0x19, 0x96, 0xd9, 0xa1, 0xe5, 0xdb, 0x81, 0xd6,
        0x40, 0x06, 0x6f, 0xec, 0x0d, 0xf0, 0x32, 0xdb,
    };

    const Block expected{
        0xeb, 0xff, 0xde, 0x3d, 0xf0, 0x06, 0x46, 0xd9,
        0x09, 0x11, 0xb7, 0x6a, 0xf8, 0x7b, 0xef, 0x78,
    };

    const Block result = mix_columns(input);

    REQUIRE(expected == result);
}

TEST_CASE("Add round key") {
    const Block input{
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    };

    const std::vector<uint8_t> key_bytes{
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    };

    const AesKey key(key_bytes);

    SECTION("Round 0") {
        const Block expected = {
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        };

        const Block result = add_round_key(input, key, 0);

        REQUIRE(expected == result);
    }

    SECTION("Round 1") {
        const Block expected = {0xd6, 0xab, 0x76, 0xfe, 0xd6, 0xaa, 0x74, 0xfd,
                                0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1};

        const Block result = add_round_key(input, key, 1);

        REQUIRE(expected == result);
    }
}

TEST_CASE("Encrypt 128") {
    const Block input{
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    };

    const std::vector<uint8_t> key_bytes{
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    };

    const Block expected{
        0x0a, 0x94, 0x0b, 0xb5, 0x41, 0x6e, 0xf0, 0x45,
        0xf1, 0xc3, 0x94, 0x58, 0xc6, 0x53, 0xea, 0x5a,
    };

    AesKey key(key_bytes);
    for (size_t i = 0; i < key.get_key().size(); i++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex
                  << (int)key.get_key()[i] << " ";
    }
    std::cout << "\n";

    const Block result = encrypt(input, key);

    REQUIRE((int)expected[0] == (int)result[0]);
    REQUIRE(expected == result);
}

TEST_CASE("Encrypt and decrypt") {
    const Block plaintext{
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    };

    const std::vector<uint8_t> key_bytes{
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    };
    const AesKey key(key_bytes);

    const Block ciphertext = encrypt(plaintext, key);

    const Block result = decrypt(ciphertext, key);

    REQUIRE(plaintext == result);
}
