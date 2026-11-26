#include "binary/BinaryView.hpp"

#include <bit>

namespace lulz::binary {
namespace {

template <typename T>
std::optional<T> readLittle(const BinaryImage& image, std::size_t offset) noexcept {
    if (!image.contains(offset, sizeof(T))) return std::nullopt;
    const auto& data = image.bytes();
    using U = std::make_unsigned_t<T>;
    U value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        value |= static_cast<U>(data[offset + i]) << (i * 8);
    if constexpr (std::is_signed_v<T>) return std::bit_cast<T>(value);
    else return static_cast<T>(value);
}

template <typename T>
std::optional<T> readBig(const BinaryImage& image, std::size_t offset) noexcept {
    if (!image.contains(offset, sizeof(T))) return std::nullopt;
    const auto& data = image.bytes();
    using U = std::make_unsigned_t<T>;
    U value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i)
        value = static_cast<U>((value << 8) | data[offset + i]);
    if constexpr (std::is_signed_v<T>) return std::bit_cast<T>(value);
    else return static_cast<T>(value);
}

} // namespace

std::optional<std::uint8_t> BinaryView::u8(std::size_t offset) const noexcept {
    return image_.byteAt(offset);
}
std::optional<std::uint16_t> BinaryView::u16le(std::size_t offset) const noexcept {
    return readLittle<std::uint16_t>(image_, offset);
}
std::optional<std::uint32_t> BinaryView::u32le(std::size_t offset) const noexcept {
    return readLittle<std::uint32_t>(image_, offset);
}
std::optional<std::uint64_t> BinaryView::u64le(std::size_t offset) const noexcept {
    return readLittle<std::uint64_t>(image_, offset);
}
std::optional<std::uint16_t> BinaryView::u16be(std::size_t offset) const noexcept {
    return readBig<std::uint16_t>(image_, offset);
}
std::optional<std::uint32_t> BinaryView::u32be(std::size_t offset) const noexcept {
    return readBig<std::uint32_t>(image_, offset);
}
std::optional<std::uint64_t> BinaryView::u64be(std::size_t offset) const noexcept {
    return readBig<std::uint64_t>(image_, offset);
}
std::optional<std::int16_t> BinaryView::i16le(std::size_t offset) const noexcept {
    return readLittle<std::int16_t>(image_, offset);
}
std::optional<std::int32_t> BinaryView::i32le(std::size_t offset) const noexcept {
    return readLittle<std::int32_t>(image_, offset);
}
std::optional<std::int64_t> BinaryView::i64le(std::size_t offset) const noexcept {
    return readLittle<std::int64_t>(image_, offset);
}
std::optional<std::int16_t> BinaryView::i16be(std::size_t offset) const noexcept {
    return readBig<std::int16_t>(image_, offset);
}
std::optional<std::int32_t> BinaryView::i32be(std::size_t offset) const noexcept {
    return readBig<std::int32_t>(image_, offset);
}
std::optional<std::int64_t> BinaryView::i64be(std::size_t offset) const noexcept {
    return readBig<std::int64_t>(image_, offset);
}

std::optional<std::span<const std::uint8_t>> BinaryView::bytes(
    std::size_t offset, std::size_t length) const noexcept {
    if (!contains(offset, length)) return std::nullopt;
    return std::span<const std::uint8_t>(image_.bytes().data() + offset, length);
}

std::optional<std::string> BinaryView::fixedString(
    std::size_t offset, std::size_t length) const {
    const auto data = bytes(offset, length);
    if (!data) return std::nullopt;
    return std::string(data->begin(), data->end());
}

std::optional<std::string> BinaryView::cString(
    std::size_t offset, std::size_t maxLength) const {
    if (!contains(offset, maxLength)) return std::nullopt;
    const auto& data = image_.bytes();
    for (std::size_t i = 0; i < maxLength; ++i) {
        if (data[offset + i] == 0)
            return std::string(reinterpret_cast<const char*>(data.data() + offset), i);
    }
    return std::nullopt;
}

} // namespace lulz::binary
