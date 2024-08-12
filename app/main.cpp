#include <crypto/ciphermode.hpp>
#include <crypto/key.hpp>
#include <crypto/tables.hpp>
#include <cstdlib>
#include <io/io.hpp>

int main(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};

    crypto::AesKey* key;
    try {
        *key = crypto::AesKey{io.key()};
    } catch (const crypto::KeyError& err) {
        io::write_to(std::clog, err.what());
        std::exit(err.code());
    }

    crypto::Block buf{};
    std::size_t bytes_read = 0;
    while ((bytes_read = io.read(buf.begin(), crypto::BLOCK_SIZE)) ==
           crypto::BLOCK_SIZE) {
    }

    return 0;
}
