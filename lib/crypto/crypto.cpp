#include <algorithm>
#include <cassert>
#include <crypto/crypto.hpp>

namespace crypto {

Block& operator^=(Block& l, const Block& r) {
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        l.at(i) ^= r.at(i);
    }
    return l;
}

Block operator^(const Block& l, const Block& r) {
    Block ll{l};
    ll ^= r;
    return ll;
}

}  // namespace crypto
