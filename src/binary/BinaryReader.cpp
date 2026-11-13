#include "lulz/binary/BinaryReader.hpp"
namespace lulz {
Result<std::span<const std::uint8_t>> BinaryReader::slice(std::size_t o, std::size_t n) const {
    if (o > bytes_.size() || n > bytes_.size() - o) return Result<std::span<const std::uint8_t>>::failure("read outside buffer");
    return Result<std::span<const std::uint8_t>>::success(bytes_.subspan(o, n));
}
Result<std::uint8_t> BinaryReader::u8(std::size_t o) const {
    auto s = slice(o, 1); if (!s) return Result<std::uint8_t>::failure(s.error());
    return Result<std::uint8_t>::success(s.value()[0]);
}
Result<std::uint16_t> BinaryReader::u16le(std::size_t o) const {
    auto s = slice(o, 2); if (!s) return Result<std::uint16_t>::failure(s.error());
    return Result<std::uint16_t>::success(static_cast<std::uint16_t>(s.value()[0] | (s.value()[1] << 8)));
}
Result<std::uint32_t> BinaryReader::u32le(std::size_t o) const {
    auto s = slice(o, 4); if (!s) return Result<std::uint32_t>::failure(s.error());
    std::uint32_t v=0; for (unsigned i=0;i<4;++i) v |= std::uint32_t(s.value()[i]) << (8*i);
    return Result<std::uint32_t>::success(v);
}
Result<std::uint64_t> BinaryReader::u64le(std::size_t o) const {
    auto s = slice(o, 8); if (!s) return Result<std::uint64_t>::failure(s.error());
    std::uint64_t v=0; for (unsigned i=0;i<8;++i) v |= std::uint64_t(s.value()[i]) << (8*i);
    return Result<std::uint64_t>::success(v);
}
}
