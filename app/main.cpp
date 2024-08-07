#include <format>
#include <io/io.hpp>

int main(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};
    std::cout << "lkasdflkjsd" << std::endl;

    crypto::Block buf{};
    std::size_t bytes_read = 0;
    while ((bytes_read = io.read(buf)) == crypto::BLOCK_SIZE) {
        std::cout << std::format("read {} bytes", bytes_read) << std::endl;
    }

    // last block
    std::cout << std::format("read {} bytes", bytes_read) << std::endl;

    return 0;
}
