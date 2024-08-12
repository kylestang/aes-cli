#include <crypto/ciphermode.hpp>
#include <crypto/key.hpp>
#include <crypto/tables.hpp>
#include <cstdio>
#include <cstdlib>
#include <io/io.hpp>

using crypto::ciphermode::CBC;
using crypto::ciphermode::CipherMode;
using crypto::ciphermode::ECB;
using crypto::ciphermode::GCM;
using io::ModeOfOperation;
namespace gcm_utils = crypto::ciphermode::gcm_utils;

int run(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};

    crypto::AesKey key{io.key()};
    std::istream& input_fd = io.input_fd();
    std::ostream& output_fd = io.output_fd();
    const io::Command& cmd = io.cmd();

    std::unique_ptr<CipherMode> cipher;
    io::ModeOfOperation mode{io.mode_of_op()};

    if (mode == ModeOfOperation::GCM) {
        crypto::Buffer iv{};
        iv.resize(crypto::BLOCK_SIZE);
        // 12 bytes random, 4 bytes 0 (counter bytes)
        crypto::fill_bytes_n(iv, gcm_utils::IV_SIZE);

        cipher = std::unique_ptr<CipherMode>{
            dynamic_cast<CipherMode*>(new GCM{key, iv})};

    } else if (mode == ModeOfOperation::CBC) {
        crypto::Buffer iv{};
        iv.resize(crypto::BLOCK_SIZE);
        crypto::fill_bytes_n(iv, crypto::BLOCK_SIZE);

        cipher = std::unique_ptr<CipherMode>{
            dynamic_cast<CipherMode*>(new CBC{key, iv})};

    } else {  // ModeOfOperation::ECB
        cipher = std::unique_ptr<CipherMode>{
            dynamic_cast<CipherMode*>(new ECB{key})};
    }

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
