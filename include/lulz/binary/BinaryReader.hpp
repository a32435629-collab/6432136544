#pragma once
#include "lulz/core/Result.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz {
class BinaryReader {
public:
    explicit BinaryReader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
    std::size_t size() const noexcept { return bytes_.size(); }
    Result<std::uint8_t> u8(std::size_t offset) const;
    Result<std::uint16_t> u16le(std::size_t offset) const;
    Result<std::uint32_t> u32le(std::size_t offset) const;
    Result<std::uint64_t> u64le(std::size_t offset) const;
    Result<std::span<const std::uint8_t>> slice(std::size_t offset, std::size_t length) const;
private:
    std::span<const std::uint8_t> bytes_;
};
}
