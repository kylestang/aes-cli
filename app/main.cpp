#include <io/io.hpp>

int main(int arg, char* argv[]) {
    const io::IO io{io::parse_cli(arg, argv)};

    return 0;
}
