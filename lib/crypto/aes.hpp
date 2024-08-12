#include <crypto/crypto.hpp>
#include <crypto/key.hpp>

namespace crypto {
Block sub_bytes(const Block matrix);
Block encrypt(Block block, AesKey key);
Block shift_rows(const Block matrix);
Block inv_shift_rows(const Block matrix);
Block mix_columns(const Block matrix);
Block inv_mix_columns(const Block matrix);
Block add_round_key(Block block, AesKey aes_key, size_t round);
Block encrypt(Block block, AesKey key);
Block decrypt(Block block, AesKey key);
}  // namespace crypto
