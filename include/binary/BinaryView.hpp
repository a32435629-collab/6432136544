#pragma once
#include "binary/BinaryImage.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>

namespace lulz::binary {
class BinaryView {
public:
    explicit BinaryView(const BinaryImage& image) : image_(image) {}
    bool contains(std::size_t offset, std::size_t length) const noexcept { return image_.contains(offset,length); }
    std::optional<std::uint16_t> u16le(std::size_t offset) const noexcept;
    std::optional<std::uint32_t> u32le(std::size_t offset) const noexcept;
    std::optional<std::uint64_t> u64le(std::size_t offset) const noexcept;
    const BinaryImage& image() const noexcept { return image_; }
private:
    const BinaryImage& image_;
};
}
