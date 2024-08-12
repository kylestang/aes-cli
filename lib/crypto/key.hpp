#pragma once

#include <crypto/tables.hpp>
#include <cstdint>
#include <errors/errors.hpp>
#include <format>
#include <string>
#include <vector>

namespace crypto {

class KeyError : public std::exception {
    private:
        const std::string msg_;
        const errors::Error err_;

    public:
        KeyError(std::string message)
            : msg_{message}, err_{errors::Error::InvalidKey} {}
        KeyError(std::string message, errors::Error err)
            : msg_{message}, err_{err} {}
        ~KeyError() = default;

        const char* what() const noexcept { return msg_.c_str(); }

        const int code() const noexcept { return err_; }

        KeyError() = delete;
        KeyError(KeyError&) = delete;
        KeyError(KeyError&&) = delete;
        KeyError& operator=(KeyError&) = delete;
        KeyError& operator=(KeyError&&) = delete;
};

class AesKey {
    public:
        enum class KeySize {
            k_128 = 128,
            k_192 = 192,
            k_256 = 256,
        };

        AesKey(const std::vector<uint8_t>&& input_key) {
            switch (input_key.size()) {
                case 16:
                    this->key = input_key;
                    this->rounds = 10;
                    key_size = KeySize::k_128;
                    break;
                case 24:
                    this->key = input_key;
                    this->rounds = 12;
                    key_size = KeySize::k_192;
                    break;
                case 32:
                    this->key = input_key;
                    this->rounds = 14;
                    key_size = KeySize::k_256;
                    break;
                default:
                    throw KeyError(std::format("invalid key. length: {} bytes",
                                               input_key.size()));
            }

            size_t nk = input_key.size() / 4;

            for (int i = input_key.size(); i < 16 * (rounds + 1); i += 4) {
                uint8_t temp_0 = key[i - 4];
                uint8_t temp_1 = key[i - 3];
                uint8_t temp_2 = key[i - 2];
                uint8_t temp_3 = key[i - 1];

                if (i % (nk * 4) == 0) {
                    uint8_t temp_4 = temp_0;
                    temp_0 = sub_byte(temp_1) ^ round_constants[(i / 4) / nk];
                    temp_1 = sub_byte(temp_2);
                    temp_2 = sub_byte(temp_3);
                    temp_3 = sub_byte(temp_4);
                } else if (nk > 6 && ((i / 4) % nk == 4)) {
                    temp_0 = sub_byte(temp_0);
                    temp_1 = sub_byte(temp_1);
                    temp_2 = sub_byte(temp_2);
                    temp_3 = sub_byte(temp_3);
                }

                key.push_back(key[i - input_key.size()] ^ temp_0);
                key.push_back(key[i - input_key.size() + 1] ^ temp_1);
                key.push_back(key[i - input_key.size() + 2] ^ temp_2);
                key.push_back(key[i - input_key.size() + 3] ^ temp_3);
            }
        }

        const size_t get_rounds() { return rounds; }
        const std::vector<uint8_t> get_key() { return key; }
        const KeySize get_key_size() { return key_size; }

    private:
        KeySize key_size;
        uint8_t rounds;
        std::vector<uint8_t> key;
};

}  // namespace crypto
