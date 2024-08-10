#include <algorithm>
#include <crypto/ciphermode.hpp>
#include <format>
#include <io/io.hpp>
#include <memory>

using crypto::Block;
using crypto::BLOCK_SIZE;
using crypto::Buffer;
using crypto::ciphermode::CBC;
using crypto::ciphermode::CipherMode;
using crypto::ciphermode::ECB;
using crypto::ciphermode::GCM;
using io::IO;
using io::ModeOfOperation;

namespace gcm_utils = crypto::ciphermode::gcm_utils;

int main(int arg, char* argv[]) {
    IO io{io::parse_cli(arg, argv)};

    // dummy key
    const std::vector<uint8_t> k{io.key()};
    CipherMode::AES key{};
    std::copy(k.begin(), k.end(), key.begin());

    // get mode of operation
    std::unique_ptr<CipherMode> cipher;
    io::ModeOfOperation mode{io.mode_of_op()};

    if (mode == ModeOfOperation::GCM) {
        const Buffer iv{gcm_utils::make_gcm_iv()};

        cipher = std::unique_ptr<CipherMode>{
            dynamic_cast<CipherMode*>(new GCM{key, iv})};

    } else if (mode == ModeOfOperation::CBC) {
        // TODO: a new function for this IV since CBC uses a different nonce
        const Buffer iv{gcm_utils::make_gcm_iv()};
        cipher = std::unique_ptr<CipherMode>{
            dynamic_cast<CipherMode*>(new CBC{key, iv})};

    } else {  // ModeOfOperation::ECB
        cipher = std::unique_ptr<CipherMode>{
            dynamic_cast<CipherMode*>(new ECB{key})};
    }

    assert(cipher.get() != nullptr);

    Block buf{};
    std::size_t bytes_read = 0;
    while ((bytes_read = io.read(buf.begin(), BLOCK_SIZE)) == BLOCK_SIZE) {
        std::cout << std::format("[{}]", (char*)buf.begin()) << std::endl;
        std::cout << std::format("read {} bytes", bytes_read) << std::endl;
    }

    // last block
    std::cout << std::format("read {} bytes", bytes_read) << std::endl;

    return 0;
}
