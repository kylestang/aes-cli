#include <filesystem>
#include <io/io.hpp>

using io::IO;
using io::IOError;
using io::ModeOfOperation;

IO::IO(std::string in_filename, std::string out_filename, std::string key,
       ModeOfOperation mode) {
    // (optional) input output files
    if (in_filename.size()) {
        if (!std::filesystem::exists(in_filename)) {
            throw IOError{
                std::format("Input file not found: {}.", in_filename)};
        }

        inputfile_ = std::ifstream{in_filename};

        if (!inputfile_->is_open()) {
            throw IOError{
                std::format("Failed to open input file: {}.", in_filename)};
        }
    }

    // (optional) input output files
    if (out_filename.size()) {
        if (std::filesystem::exists(out_filename)) {
            throw IOError{std::format("Output file exists: {}.", out_filename)};
        }

        outputfile_ = std::ofstream{out_filename};

        if (!outputfile_->is_open()) {
            throw IOError{
                std::format("Failed to open output file: {}.", out_filename)};
        }
    }

    // (optional) key
    // if key not fed from cli, read from env args
    io::key_parser(key, key_);
    std::cout << "HELKRJLKJ" << std::endl;

    // mode
    mode_ = mode;
}

io::Key IO::key() const { return key_; }

io::ModeOfOperation IO::mode_of_op() const { return mode_; };

std::size_t IO::read(crypto::Block& buf) {
    std::size_t s = crypto::BLOCK_SIZE;
    if (inputfile_) {
        return inputfile_->readsome((char*)buf.begin(), s);
    }
    return std::cin.readsome((char*)buf.begin(), s);
}

void IO::write(char* buf) {
    if (outputfile_) {
        write_to(*outputfile_, buf);
    } else {
        write_to(std::cout, buf);
    }
}
