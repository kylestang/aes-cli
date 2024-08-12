#include <crypto/ciphermode.hpp>
#include <crypto/key.hpp>
#include <crypto/tables.hpp>
#include <cstdio>
#include <cstdlib>
#include <io/io.hpp>

int run(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};

    crypto::AesKey key{io.key()};
    std::istream& input_fd = io.input_fd();
    std::ostream& output_fd = io.output_fd();
    const io::Command& cmd = io.cmd();

    crypto::Block buf{};
    std::size_t bytes_read =
        input_fd.readsome((char*)buf.begin(), crypto::BLOCK_SIZE);
    while (true) {
        const bool is_eof = input_fd.peek() == EOF;
        if (is_eof) {
            if (cmd == io::Command::Encrypt) {

            } else {
            }

            io::Writer::write_to(std::cout, "end of file\n");
            break;
        }

        io::Writer::write_to(std::cout, "Process `buf`");
        if (cmd == io::Command::Encrypt) {
        } else {
        }

        bytes_read = input_fd.readsome((char*)buf.begin(), crypto::BLOCK_SIZE);
        io::Writer::write_to(std::cout,
                             std::format("read {} bytes\n", bytes_read));
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
