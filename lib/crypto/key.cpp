
#include <crypto/aes.hpp>
#include <crypto/tables.hpp>
#include <cstdint>
#include <vector>

namespace crypto {

class AesKey {
    public:
        enum class KeySize {
            k_128 = 128,
            k_192 = 192,
            k_256 = 256,
        };

        AesKey(const std::vector<uint8_t> input_key) {
            switch (key.size()) {
                case 128:
                    this->key = input_key;
                    this->rounds = 10;
                    key_size = KeySize::k_128;
                    break;
                case 192:
                    this->key = input_key;
                    this->rounds = 12;
                    key_size = KeySize::k_192;
                    break;
                case 256:
                    this->key = input_key;
                    this->rounds = 14;
                    key_size = KeySize::k_256;
                    break;
                default:
                    // TODO: Custom error type
                    throw "Invalid key";
            }

            int nk = input_key.size() / 4;

            for (int i = input_key.size(); i < 16 * (rounds + 1); i += 4) {
                uint8_t temp_0 = key[i - 4];
                uint8_t temp_1 = key[i - 3];
                uint8_t temp_2 = key[i - 2];
                uint8_t temp_3 = key[i - 1];

                if (i % nk == 0) {
                    uint8_t temp_4 = temp_0;
                    temp_0 = substitution(temp_1) ^ round_constants[i / nk];
                    temp_1 = substitution(temp_2);
                    temp_2 = substitution(temp_3);
                    temp_3 = substitution(temp_4);
                } else if (nk > 6 && ((i / 4) % nk == 4)) {
                    temp_0 = substitution(temp_0);
                    temp_1 = substitution(temp_1);
                    temp_2 = substitution(temp_2);
                    temp_3 = substitution(temp_3);
                }

                key[i] = key[i - input_key.size()] ^ temp_0;
                key[i + 1] = key[i - input_key.size() + 1] ^ temp_1;
                key[i + 2] = key[i - input_key.size() + 2] ^ temp_2;
                key[i + 3] = key[i - input_key.size() + 3] ^ temp_3;
            }
        }

        const size_t get_rounds() { return rounds; }
        const std::vector<uint8_t> get_key() { return key; }

    private:
        KeySize key_size;
        uint8_t rounds;
        std::vector<uint8_t> key;
};

}  // namespace crypto
