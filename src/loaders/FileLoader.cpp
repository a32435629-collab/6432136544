#include "lulz/loaders/FileLoader.hpp"
#include <fstream>
#include <iterator>
namespace lulz {
Result<std::vector<std::uint8_t>> loadFile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return Result<std::vector<std::uint8_t>>::failure("cannot open file: " + path.string());
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    if (in.bad()) return Result<std::vector<std::uint8_t>>::failure("error while reading file");
    return Result<std::vector<std::uint8_t>>::success(std::move(data));
}
}
