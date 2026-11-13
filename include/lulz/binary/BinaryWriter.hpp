#pragma once
#include <cstdint>
#include <vector>
namespace lulz {
class BinaryWriter {
public:
    void u8(std::uint8_t v) { bytes_.push_back(v); }
    void u32le(std::uint32_t v);
    void append(const std::vector<std::uint8_t>& data);
    const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
private:
    std::vector<std::uint8_t> bytes_;
};
}
