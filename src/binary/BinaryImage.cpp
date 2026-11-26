#include "binary/BinaryImage.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace lulz::binary {

BinaryImage BinaryImage::fromBytes(std::vector<std::uint8_t> bytes, std::string source) {
    BinaryImage image;
    image.bytes_ = std::move(bytes);
    image.source_ = std::move(source);
    return image;
}

BinaryImage BinaryImage::load(const std::filesystem::path& path) {
    return load(path, BinaryLoadOptions{});
}

BinaryImage BinaryImage::load(
    const std::filesystem::path& path, const BinaryLoadOptions& options) {
    if (options.chunkSize == 0)
        throw std::invalid_argument("BinaryImage: chunk size must be greater than zero");

    std::error_code ec;
    const auto fileSize = std::filesystem::file_size(path, ec);
    if (ec)
        throw std::runtime_error("BinaryImage: unable to determine file size: " + ec.message());
    if (fileSize > options.maxBytes)
        throw std::runtime_error("BinaryImage: file exceeds configured size limit");
    if (fileSize > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max()))
        throw std::runtime_error("BinaryImage: file too large for address space");
    if (fileSize > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max()))
        throw std::runtime_error("BinaryImage: file too large for stream operations");

    const auto totalSize = static_cast<std::size_t>(fileSize);
    std::vector<std::uint8_t> data;
    data.reserve(totalSize);

    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("BinaryImage: unable to open file");

    std::vector<char> chunk(std::min(options.chunkSize, std::max<std::size_t>(totalSize, 1)));
    std::size_t remaining = totalSize;
    while (remaining != 0) {
        const auto amount = std::min(remaining, chunk.size());
        in.read(chunk.data(), static_cast<std::streamsize>(amount));
        if (in.gcount() != static_cast<std::streamsize>(amount))
            throw std::runtime_error("BinaryImage: file changed or read was incomplete");

        const auto* begin = reinterpret_cast<const std::uint8_t*>(chunk.data());
        data.insert(data.end(), begin, begin + amount);
        remaining -= amount;
    }

    // Reject growth during loading rather than silently returning a stale prefix.
    char extra = 0;
    if (in.get(extra))
        throw std::runtime_error("BinaryImage: file changed during loading");
    if (!in.eof())
        throw std::runtime_error("BinaryImage: I/O error after reading file");

    return fromBytes(std::move(data), path.string());
}

bool BinaryImage::contains(std::size_t offset, std::size_t length) const noexcept {
    return offset <= bytes_.size() && length <= bytes_.size() - offset;
}

std::optional<std::uint8_t> BinaryImage::byteAt(std::size_t offset) const noexcept {
    if (!contains(offset, 1)) return std::nullopt;
    return bytes_[offset];
}

} // namespace lulz::binary
