#include <crypto/ciphermode.hpp>
#include <format>
#include <io/io.hpp>

int main(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};

    crypto::Block buf{};
    std::size_t bytes_read = 0;
    while ((bytes_read = io.read(buf.begin(), crypto::BLOCK_SIZE)) ==
           crypto::BLOCK_SIZE) {
        std::cout << std::format("[{}]", (char*)buf.begin()) << std::endl;
        std::cout << std::format("read {} bytes", bytes_read) << std::endl;
    }

    // last block
    std::cout << std::format("read {} bytes", bytes_read) << std::endl;

    return 0;
}
