#include <unistd.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <cassert>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <errors/errors.hpp>
#include <format>
#include <fstream>
#include <iostream>
#include <optional>
#include <ostream>
#include <vector>

namespace io {

namespace po = boost::program_options;

class IOError : public std::exception {
    private:
        const std::string msg_;
        const errors::Error err_;

    public:
        IOError(std::string message)
            : msg_{message}, err_{errors::Error::InvalidArgument} {}

        IOError(std::string message, errors::Error err)
            : msg_{message}, err_{err} {}

        const char* what() const noexcept { return msg_.c_str(); }

        const int code() const noexcept { return err_; }
};

template <class CharT, class Traits = std::char_traits<CharT>, class T>
void write_to(std::basic_ostream<CharT, Traits>& stream, const T& t) noexcept {
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
inline ModeOfOperation mode_op_parser(const std::string& mode) {
    // default to GCM
    if (mode.size() == 0) {
        return ModeOfOperation::GCM;
    }

    std::string mode_lower{mode};

    const auto fn = [](char in) -> char { return std::tolower(in); };
    std::transform(mode_lower.begin(), mode_lower.end(), mode_lower.begin(),
                   fn);

    const bool is_gcm = mode_lower == "gcm";
    const bool is_cbc = mode_lower == "cbc";
    const bool is_ecb = mode_lower == "ecb";

    if (!is_gcm && !is_cbc && !is_ecb) {
        throw IOError{"Invalid mode of operation.",
                      errors::Error::InvalidArgument};
    }

    if (is_gcm) {
        return ModeOfOperation::GCM;
    } else if (is_cbc) {
        return ModeOfOperation::CBC;
    } else {  // is_ecb
        return ModeOfOperation::ECB;
    }
}

using Key = std::vector<char>;

inline void key_parser(Key& key) {
    // (optional) key
    // if key not fed from cli, read from env args
    if (key.size() == 0) {
        const std::string key_env = std::getenv("AES_CLI_KEY");
        key.reserve(key_env.size());
        for (std::size_t i = 0; i < key_env.size(); ++i) {
            key.push_back(key_env.at(i));
        }
    }

    // key size correct?
    const std::size_t keylen = key.size();
    const bool valid_keylen = keylen == 16 || keylen == 24 || keylen == 32;

    if (!valid_keylen) {
        throw IOError{"invalid length input key", errors::Error::InvalidKey};
    }
}

class IO {
    private:
        // if inputfile is none, read from stdin
        std::optional<std::ifstream> inputfile_{std::nullopt};

        // if outputfile is none, write to stdout
        std::optional<std::ofstream> outputfile_{std::nullopt};

        Key key_{};

        ModeOfOperation mode_;

    public:
        IO(std::string in_filename, std::string out_filename, std::string key,
           ModeOfOperation mode);

        Key key() const;

        ModeOfOperation mode_of_op() const;

        std::size_t read(char* buf, std::size_t s);

        void write(char* buf);
};

inline IO parse_cli(int ac, char* av[]) noexcept {
    using InvalidArgument =
        boost::wrapexcept<boost::program_options::unknown_option>;

    try {
        std::string input_file, output_file, key, mode;

        po::options_description desc{"Usage"};
        auto opt = desc.add_options();
        opt("input,i", po::value<std::string>(&input_file),
            "(optional) input file");
        opt("output,o", po::value<std::string>(&output_file),
            "(optional) output file");
        opt("mode,m", po::value<std::string>(&mode),
            "set mode of operation, default to GCM");
        opt("key,k", po::value<std::string>(&key),
            "(optional) input key, of length 128, 192, 256 bits");
        opt("help,h", "print this help message and exit");

        po::variables_map vm;
        po::store(po::command_line_parser(ac, av).options(desc).run(), vm);
        po::notify(vm);

        // if --help
        if (vm.count("help")) {
            write_to(std::cout, desc);
            std::exit(0);
        }

        return IO{input_file, output_file, key, mode_op_parser(mode)};

    } catch (const IOError& err) {
        write_to(std::clog, std::format("{}\n", err.what()));
        std::exit(err.code());

    } catch (const InvalidArgument& err) {
        write_to(std::clog, std::format("{}\n", err.what()));
        std::exit(errors::Error::InvalidArgument);

    } catch (...) {
        write_to(std::cerr, "io: something went wrong with parsing cli args\n");
        std::abort();
    }
}

}  // namespace io
