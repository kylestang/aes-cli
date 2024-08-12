#include <cassert>
#include <crypto/ciphermode.hpp>
#include <crypto/key.hpp>
#include <crypto/tables.hpp>
#include <cstdio>
#include <cstdlib>
#include <io/io.hpp>

#include "crypto/crypto.hpp"

namespace gcm_utils = crypto::ciphermode::gcm_utils;

int run(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};

    crypto::AesKey key{io.key()};
    std::istream& input_fd = io.input_fd();
    std::ostream& output_fd = io.output_fd();
    const io::Command& cmd = io.cmd();

    io::ModeOfOperation mode{io.mode_of_op()};

    if (mode == io::ModeOfOperation::GCM) {
        if (io.cmd() == io::Command::Encrypt) {
            // make iv
            crypto::Buffer iv{gcm_utils::IV_SIZE};
            crypto::fill_bytes_n(iv, gcm_utils::IV_SIZE);
            io::Writer::write_bytes(output_fd, iv);

            iv.resize(crypto::BLOCK_SIZE);
            crypto::ciphermode::GCM cipher{key, input_fd, output_fd, iv};
            cipher.encrypt_fd();

        } else {
            std::array<uint8_t, gcm_utils::IV_SIZE> block;
            const std::size_t bytes_read =
                input_fd.readsome((char*)block.begin(), gcm_utils::IV_SIZE);

            crypto::Buffer iv{};
            iv.resize(crypto::BLOCK_SIZE);
            std::copy(block.begin(), block.end(), iv.begin());

            crypto::ciphermode::GCM cipher{key, input_fd, output_fd, iv};
            cipher.decrypt_fd();
        }

    } else if (mode == io::ModeOfOperation::CBC) {
        if (io.cmd() == io::Command::Encrypt) {
            // make iv
            crypto::Buffer iv{};
            crypto::fill_bytes_n(iv, crypto::BLOCK_SIZE);
            io::Writer::write_bytes(output_fd, iv);

            crypto::ciphermode::CBC cipher{key, input_fd, output_fd, iv};
            cipher.encrypt_fd();
        } else {
            std::array<uint8_t, crypto::BLOCK_SIZE> block;
            const std::size_t bytes_read =
                input_fd.readsome((char*)block.begin(), gcm_utils::IV_SIZE);

            crypto::Buffer iv{};
            iv.resize(crypto::BLOCK_SIZE);
            std::copy(block.begin(), block.end(), iv.begin());

            crypto::ciphermode::GCM cipher{key, input_fd, output_fd, iv};
            cipher.decrypt_fd();
        }

    } else {  // ModeOfOperation::ECB
        crypto::Buffer iv{};
        crypto::ciphermode::ECB gcm{key, input_fd, output_fd, iv};
        if (io.cmd() == io::Command::Encrypt) {
            gcm.encrypt_fd();
        } else {
            gcm.decrypt_fd();
        }
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
