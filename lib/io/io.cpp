#include <filesystem>
#include <format>
#include <io/io.hpp>
#include <string>

using io::IO;
using io::IOError;
using io::Key;
using io::ModeOfOperation;

IOError::IOError(std::string message)
    : msg_{message}, err_{errors::Error::InvalidArgument} {}

IOError::IOError(std::string message, errors::Error err)
    : msg_{message}, err_{err} {}

const char* IOError::what() const noexcept { return msg_.c_str(); }

const int IOError::code() const noexcept { return err_; }

template <class CharT, class Traits, class T>
void io::write_to(std::basic_ostream<CharT, Traits>& stream,
                  const T& t) noexcept {
    stream << t;
    if (stream.flush().bad()) {
        std::clog << "write failed\n" << t << std::endl;
        if (std::clog.bad()) std::abort();
    }
}

IO::IO(std::string in_filename, std::string out_filename, Key key,
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
    key_ = key;

    // mode
    mode_ = mode;
}

Key IO::key() const { return key_; }

ModeOfOperation IO::mode_of_op() const { return mode_; };

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

// Parsing mode of operation string
ModeOfOperation io::mode_op_parser(const std::string& mode) {
    // default to GCM
    if (mode.size() == 0) {
        return ModeOfOperation::GCM;
    }

    std::string mode_lower{};
    mode_lower.resize(mode.length());

    const auto fn = [](unsigned char in) -> unsigned char {
        return std::tolower(in);
    };
    std::transform(mode.begin(), mode.end(), mode_lower.begin(), fn);

    const bool is_gcm = mode_lower == "gcm";
    const bool is_cbc = mode_lower == "cbc";
    const bool is_ecb = mode_lower == "ecb";

    if (is_gcm) {
        return ModeOfOperation::GCM;
    } else if (is_cbc) {
        return ModeOfOperation::CBC;
    } else if (is_ecb) {
        return ModeOfOperation::ECB;
    } else {
        throw IOError{std::format("Invalid mode of operation: [{}]", mode),
                      errors::Error::InvalidArgument};
    }
}

Key io::key_parser(const std::string& key_arg) {
    Key key{};

    // (optional) key
    // if key not fed from cli, read from env args
    if (key_arg.size() == 0) {
        const char* key_env = std::getenv("AES_CLI_KEY");
        if (!key_env) {
            throw IOError{"env variable not set: AES_CLI_KEY"};
        }

        const std::string env_string{key_env};

        key.resize(env_string.size());
        std::copy(env_string.begin(), env_string.end(), key.begin());

    } else {
        // copy key_arg to key_buf
        for (std::size_t i = 0; i < key_arg.size(); ++i) {
            key.push_back(key_arg.at(i));
        }
    }

    // key size correct?
    const std::size_t keylen = key.size();
    const bool valid_keylen = keylen == 16 || keylen == 24 || keylen == 32;

    if (!valid_keylen) {
        throw IOError{"invalid length input key", errors::Error::InvalidKey};
    }

    return key;
}

io::IO io::parse_cli(int ac, char* av[]) noexcept {
    namespace po = boost::program_options;
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

        return IO{input_file, output_file, key_parser(key),
                  mode_op_parser(mode)};

    } catch (const IOError& err) {
        write_to(std::clog, std::format("{}\n", err.what()));
        std::exit(err.code());

    } catch (const InvalidArgument& err) {
        write_to(std::clog, std::format("{}\n", err.what()));
        std::exit(errors::Error::InvalidArgument);

    } catch (...) {
        std::exception_ptr p = std::current_exception();
        write_to(std::clog, "io: something went wrong with parsing cli args\n");
        std::clog << (p ? p.__cxa_exception_type()->name() : "null")
                  << std::endl;
        std::exit(errors::Error::Other);
    }
}
