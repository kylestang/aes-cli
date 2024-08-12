#include <cassert>
#include <crypto/ciphermode.hpp>
#include <crypto/key.hpp>
#include <crypto/tables.hpp>
#include <cstdio>
#include <cstdlib>
#include <io/io.hpp>

#include "crypto/crypto.hpp"

std::string print_block(crypto::Block& block) {
    std::ostringstream result;
    for (std::size_t i = 0; i < block.size(); i++) {
        result << std::setfill('0') << std::setw(2) << std::hex << (int)block[i]
               << " ";
    }
    result << "\n";
    return result.str();
}

namespace gcm_utils = crypto::ciphermode::gcm_utils;

int run(int arg, char* argv[]) {
    io::IO io{io::parse_cli(arg, argv)};

    crypto::AesKey key{io.key()};
    std::istream& input_fd = io.input_fd();
    std::ostream& output_fd = io.output_fd();

    io::ModeOfOperation mode{io.mode_of_op()};

    if (mode == io::ModeOfOperation::GCM) {
        if (io.cmd() == io::Command::Encrypt) {
            // make iv
            crypto::Block iv{};
            crypto::fill_bytes_n(iv, gcm_utils::IV_SIZE);
            io::Writer::write_block(output_fd, iv, gcm_utils::IV_SIZE);
            crypto::ciphermode::GCM cipher{key, input_fd, output_fd, iv};
            cipher.encrypt_fd();

        } else {
            crypto::Block iv;
            const std::size_t bytes_read =
                input_fd.readsome((char*)iv.data(), gcm_utils::IV_SIZE);

            crypto::ciphermode::GCM cipher{key, input_fd, output_fd, iv};
            cipher.decrypt_fd();
        }

    } else if (mode == io::ModeOfOperation::CBC) {
        if (io.cmd() == io::Command::Encrypt) {
            // make iv
            crypto::Block iv{};
            crypto::fill_bytes_n(iv, crypto::BLOCK_SIZE);
            io::Writer::write_block(output_fd, iv, crypto::BLOCK_SIZE);
            crypto::ciphermode::CBC cipher{key, input_fd, output_fd, iv};
            cipher.encrypt_fd();
        } else {
            crypto::Block iv;
            const std::size_t bytes_read =
                input_fd.readsome((char*)iv.data(), crypto::BLOCK_SIZE);

            crypto::ciphermode::CBC cipher{key, input_fd, output_fd, iv};
            cipher.decrypt_fd();
        }

    } else {  // ModeOfOperation::ECB
        crypto::Block iv{};
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
