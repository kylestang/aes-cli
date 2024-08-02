#include <unistd.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <errors/errors.hpp>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <istream>
#include <mutex>
#include <optional>
#include <ostream>

namespace io {

namespace po = boost::program_options;

using Bytes = char;

class IOError : public std::exception {
   private:
    const std::string msg_;

   public:
    IOError(std::string message) : msg_{message} {}

    const char* what() const noexcept { return msg_.c_str(); }

    const int code() const noexcept { return errors::Error::InvalidArgument; }
};

class InputStream {
   public:
    virtual std::size_t read(Bytes* buf, std::size_t size);
    virtual ~InputStream() = default;
};

class OutputStream {
   public:
    virtual void write(const Bytes* buf, std::size_t size);
    virtual ~OutputStream() = default;
};

class StdIn : public InputStream {
   public:
    StdIn() {}
    std::size_t read(Bytes* buf, std::size_t size) {
        std::cin.read(buf, size);
        return std::cin.gcount();
    };
};

class StdOut : public OutputStream {
   public:
    StdOut() {}
    void write(Bytes* buf, std::size_t size) {
        std::cout.write(buf, size);
        if (std::cout.bad()) {
            throw IOError{"Failed to write to standard output"};
        }
    };
    ~StdOut() {
        std::cout.flush();
        assert(!std::cout.bad());
    }
};

class InputFile : public InputStream {
   private:
    std::ifstream file_;

   public:
    InputFile(std::string filename) : file_{std::ifstream{filename}} {
        if (!file_.is_open()) {
            throw IOError(std::format("file not found: {}", filename));
        }
    }
    std::size_t read(Bytes* buf, std::size_t bytes) {
        file_.read(buf, bytes);
        return file_.gcount();
    };
};

class OutputFile : public OutputStream {
   private:
    std::ofstream file_;

   public:
    OutputFile(std::string filename) : file_{std::ofstream{filename}} {
        if (!file_.is_open()) {
            throw IOError(std::format("failed to open file: {}", filename));
        }
    }
    void write(Bytes* buf, std::size_t size) {
        file_.write(buf, size);
        if (std::cout.bad()) {
            throw IOError{"Failed to write to standard output"};
        }
    };
    ~OutputFile() {
        file_.flush();
        assert(!file_.bad());
    }
};

class IO {
   private:
    using InvalidArgument =
        boost::wrapexcept<boost::program_options::unknown_option>;

    InputStream input_stream;
    OutputStream output_stream;

   public:
    IO(int ac, char* av[]) {
        std::string input_file, output_file;

        po::options_description desc{"Usage"};
        auto opt = desc.add_options();
        opt("help", "produce help message");
        opt("input", po::value<std::string>(&input_file), "input file");
        opt("output", po::value<std::string>(&output_file), "output file");

        // positional args
        // po::positional_options_description p;

        po::variables_map vm;
        try {
            po::store(po::command_line_parser(ac, av)
                          .options(desc)
                          // .positional(p)
                          .run(),
                      vm);
            po::notify(vm);

            // if --help
            if (vm.count("help")) {
                std::cout << desc << std::endl;
                std::exit(0);
            }

            // (optional) input output files
            if (input_file.length()) {
                if (!std::filesystem::exists(input_file)) {
                    throw IOError{
                        std::format("Input file not found: {}.", input_file)};
                }
                input_stream = InputFile{input_file};
            } else {
                input_stream = StdIn{};
            }

            // (optional) input output files
            if (output_file.length()) {
                if (std::filesystem::exists(output_file)) {
                    throw IOError{
                        std::format("Output file exists: {}.", output_file)};
                }
                output_stream = OutputFile{output_file};
            } else {
                output_stream = StdOut{};
            }

        } catch (const InvalidArgument& err) {
            std::clog << err.what() << std::endl;
            std::exit(errors::Error::InvalidArgument);

        } catch (const IOError& err) {
            std::clog << err.what() << std::endl;
            std::exit(err.code());

        } catch (...) {
            const std::exception_ptr p = std::current_exception();
            std::clog << (p ? p.__cxa_exception_type()->name() : "null")
                      << std::endl;
            std::exit(errors::Error::Other);
        }
    }
};

}  // namespace io
