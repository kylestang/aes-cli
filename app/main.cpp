#include <crypto/ciphermode.hpp>
#include <crypto/key.hpp>
#include <crypto/tables.hpp>
#include <cstdlib>
#include <io/io.hpp>

int run(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};

    crypto::AesKey key{io.key()};

    crypto::Block buf{};
    std::size_t bytes_read = 0;
    while ((bytes_read = io.read(buf.begin(), crypto::BLOCK_SIZE)) ==
           crypto::BLOCK_SIZE) {
    }

    return 0;
}

int main(int arg, char* argv[]) {
    try {
        return run(arg, argv);

    } catch (const crypto::KeyError& err) {
        io::Writer::write_to(std::clog, err.what());
        return err.code();

    } catch (const io::IOError& err) {
        io::Writer::write_to(std::clog, err.what());
        return err.code();
    }
}
