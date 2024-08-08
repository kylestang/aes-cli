
#include <cstdint>
#include <vector>
namespace aes {

class AesKey {
    public:
        enum class KeySize {
            k_128 = 128,
            k_192 = 192,
            k_256 = 256,
        };

        AesKey(const std::vector<uint8_t> key) {
            switch (key.size()) {
            case 128:
                this->key = key;
                key_size = KeySize::k_128;
                break;
            case 192:
                this->key = key;
                key_size = KeySize::k_192;
                break;
            case 256:
                this->key = key;
                key_size = KeySize::k_256;
                break;
            default:
                // TODO: Custom error type
                throw "Invalid key";
            }
        }

    private:
        KeySize key_size;
        std::vector<uint8_t> key;
};

} // namespace aes
