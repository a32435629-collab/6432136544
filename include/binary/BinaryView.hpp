#pragma once

#include "binary/BinaryImage.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace lulz::binary {

// A bounds-checked, non-owning view over an immutable BinaryImage.
// Returned spans refer to the image and remain valid while that image is alive.
class BinaryView {
public:
    explicit BinaryView(const BinaryImage& image) noexcept : image_(image) {}

    bool contains(std::size_t offset, std::size_t length) const noexcept {
        return image_.contains(offset, length);
    }

    std::optional<std::uint8_t> u8(std::size_t offset) const noexcept;
    std::optional<std::uint16_t> u16le(std::size_t offset) const noexcept;
    std::optional<std::uint32_t> u32le(std::size_t offset) const noexcept;
    std::optional<std::uint64_t> u64le(std::size_t offset) const noexcept;
    std::optional<std::uint16_t> u16be(std::size_t offset) const noexcept;
    std::optional<std::uint32_t> u32be(std::size_t offset) const noexcept;
    std::optional<std::uint64_t> u64be(std::size_t offset) const noexcept;

    std::optional<std::int16_t> i16le(std::size_t offset) const noexcept;
    std::optional<std::int32_t> i32le(std::size_t offset) const noexcept;
    std::optional<std::int64_t> i64le(std::size_t offset) const noexcept;
    std::optional<std::int16_t> i16be(std::size_t offset) const noexcept;
    std::optional<std::int32_t> i32be(std::size_t offset) const noexcept;
    std::optional<std::int64_t> i64be(std::size_t offset) const noexcept;

    // Zero-copy byte access. The span is valid only as long as image_ is alive.
    std::optional<std::span<const std::uint8_t>> bytes(
        std::size_t offset, std::size_t length) const noexcept;

    // Reads exactly length bytes as text; embedded NUL bytes are preserved.
    std::optional<std::string> fixedString(
        std::size_t offset, std::size_t length) const;

    // Reads at most maxLength bytes and requires a NUL terminator in that range.
    std::optional<std::string> cString(
        std::size_t offset, std::size_t maxLength) const;

    const BinaryImage& image() const noexcept { return image_; }

private:
    const BinaryImage& image_;
};

} // namespace lulz::binary
