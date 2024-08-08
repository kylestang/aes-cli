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

        AesKey(const std::vector<uint8_t> key);

    private:
        KeySize key_size;
        std::vector<uint8_t> key;
};

} // namespace aes
