#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace lulz::binary {
class BinaryImage {
public:
    static BinaryImage fromBytes(std::vector<std::uint8_t> bytes, std::string source = {});
    static BinaryImage load(const std::filesystem::path& path);
    const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
    const std::string& source() const noexcept { return source_; }
    std::size_t size() const noexcept { return bytes_.size(); }
    bool contains(std::size_t offset, std::size_t length) const noexcept;
    std::optional<std::uint8_t> byteAt(std::size_t offset) const noexcept;
private:
    std::vector<std::uint8_t> bytes_;
    std::string source_;
};
}
