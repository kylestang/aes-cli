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

class Writer {
    public:
        template <class T>
        static inline void write_err(const T& t) noexcept {
            std::clog << t << std::endl;
            if (std::clog.bad()) std::abort();
        }

        template <class CharT, class Traits = std::char_traits<CharT>, class T>
        static inline void write_to(std::basic_ostream<CharT, Traits>& stream,
                                    const T& t) noexcept {
            stream << t;
            if (stream.flush().bad()) {
                std::clog << "write failed\n" << t << std::endl;
                if (std::clog.bad()) std::abort();
            }
        }

        template <class CharT, class Traits = std::char_traits<CharT>, class T>
        static inline void dbg(std::basic_ostream<CharT, Traits>& stream,
                               const T& t) noexcept {
#ifdef DEBUG
            stream << "[DEBUG] " << t << std::endl;
            if (stream.flush().bad()) {
                std::clog << "write failed\n" << t << std::endl;
                if (std::clog.bad()) std::abort();
            }
#endif
        }
};

enum ModeOfOperation : char {
    GCM = 1,
    CBC,
    ECB,
};

// Parsing mode of operation string
ModeOfOperation mode_op_parser(const std::string& mode);

Key key_parser(const std::string& key_arg);

enum Command : char {
    Encrypt,
    Decrypt,
};

Command command_parser(const std::string& command);

class IO {
    private:
        // if inputfile is none, read from stdin
        std::optional<std::ifstream> inputfile_{std::nullopt};

        // if outputfile is none, write to stdout
        std::optional<std::ofstream> outputfile_{std::nullopt};

        const Key key_{};

        const ModeOfOperation mode_;

        const Command cmd_;

    public:
        IO(std::string in_filename, std::string out_filename, Key key,
           ModeOfOperation mode, Command cmd);

        ~IO() = default;

        Key key() const;

        ModeOfOperation mode_of_op() const;

        std::istream& input_fd();
        std::ostream& output_fd();
    const Command& cmd() const noexcept;

        IO() = delete;
        IO(IO&) = delete;
        IO(IO&&) = delete;
        IO& operator=(IO&) = delete;
        IO& operator=(IO&&) = delete;
};

IO parse_cli(int ac, char* av[]) noexcept;

}  // namespace io
