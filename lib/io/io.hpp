#include <unistd.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <cassert>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <errors/errors.hpp>
#include <fstream>
#include <iostream>
#include <optional>
#include <ostream>
#include <vector>

namespace io {

using Key = std::vector<uint8_t>;

class IOError : public std::exception {
    private:
        const std::string msg_;
        const errors::Error err_;

    public:
        IOError(std::string message);
        IOError(std::string message, errors::Error err);
        ~IOError() = default;

        const char* what() const noexcept;

        const int code() const noexcept;

        IOError() = delete;
        IOError(IOError&) = delete;
        IOError(IOError&&) = delete;
        IOError& operator=(IOError&) = delete;
        IOError& operator=(IOError&&) = delete;
};

template <class CharT, class Traits = std::char_traits<CharT>, class T>
inline void write_to(std::basic_ostream<CharT, Traits>& stream, const T& t) noexcept {
    stream << t;
    if (stream.flush().bad()) {
        std::clog << "write failed\n" << t << std::endl;
        if (std::clog.bad()) std::abort();
    }
}

enum ModeOfOperation : int {
    GCM = 1,
    CBC,
    ECB,
};

// Parsing mode of operation string
ModeOfOperation mode_op_parser(const std::string& mode);

Key key_parser(const std::string& key_arg);

class IO {
    private:
        // if inputfile is none, read from stdin
        std::optional<std::ifstream> inputfile_{std::nullopt};

        // if outputfile is none, write to stdout
        std::optional<std::ofstream> outputfile_{std::nullopt};

        Key key_{};

        ModeOfOperation mode_;

    public:
        IO(std::string in_filename, std::string out_filename, Key key,
           ModeOfOperation mode);

        ~IO() = default;

        Key key() const;

        ModeOfOperation mode_of_op() const;

        std::size_t read(uint8_t* iter_start, std::size_t n);

        void write(char* buf);

        IO() = delete;
        IO(IO&) = delete;
        IO(IO&&) = delete;
        IO& operator=(IO&) = delete;
        IO& operator=(IO&&) = delete;
};

IO parse_cli(int ac, char* av[]) noexcept;

}  // namespace io
