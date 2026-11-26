#include "binary/BinaryImage.hpp"
#include <fstream>
#include <limits>
#include <stdexcept>

namespace lulz::binary {
BinaryImage BinaryImage::fromBytes(std::vector<std::uint8_t> bytes, std::string source) {
    BinaryImage image; image.bytes_ = std::move(bytes); image.source_ = std::move(source); return image;
}
BinaryImage BinaryImage::load(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("BinaryImage: unable to open file");
    const auto end = in.tellg();
    if (end < 0) throw std::runtime_error("BinaryImage: unable to determine file size");
    const auto size = static_cast<std::uintmax_t>(end);
    if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max()))
        throw std::runtime_error("BinaryImage: file too large for address space");
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    in.seekg(0, std::ios::beg);
    if (!data.empty() && !in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size())))
        throw std::runtime_error("BinaryImage: read failed");
    return fromBytes(std::move(data), path.string());
}
bool BinaryImage::contains(std::size_t offset, std::size_t length) const noexcept {
    return offset <= bytes_.size() && length <= bytes_.size() - offset;
}
std::optional<std::uint8_t> BinaryImage::byteAt(std::size_t offset) const noexcept {
    if (!contains(offset, 1)) return std::nullopt;
    return bytes_[offset];
}
}
