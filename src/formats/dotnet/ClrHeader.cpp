#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
namespace lulz::formats::dotnet {struct ClrHeader{std::uint32_t size,metadataRva,metadataSize,flags,entryToken;std::uint16_t major,minor;};static std::uint16_t u16(std::span<const std::uint8_t>b,std::size_t o){return b[o]|(std::uint16_t(b[o+1])<<8);}static std::uint32_t u32(std::span<const std::uint8_t>b,std::size_t o){return b[o]|(std::uint32_t(b[o+1])<<8)|(std::uint32_t(b[o+2])<<16)|(std::uint32_t(b[o+3])<<24);}std::optional<ClrHeader> parse(std::span<const std::uint8_t>b,std::size_t o){if(o>b.size()||b.size()-o<24)return {};ClrHeader h{u32(b,o),u32(b,o+8),u32(b,o+12),u32(b,o+16),u32(b,o+20),u16(b,o+4),u16(b,o+6)};if(h.size<24||h.size>b.size()-o||!h.metadataRva||!h.metadataSize)return {};return h;} }