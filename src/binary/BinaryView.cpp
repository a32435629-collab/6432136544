#include "binary/BinaryView.hpp"
namespace lulz::binary {
std::optional<std::uint16_t> BinaryView::u16le(std::size_t o) const noexcept {
 if(!contains(o,2)) return {}; const auto& b=image_.bytes(); return static_cast<std::uint16_t>(b[o] | (static_cast<std::uint16_t>(b[o+1])<<8));
}
std::optional<std::uint32_t> BinaryView::u32le(std::size_t o) const noexcept {
 if(!contains(o,4)) return {}; const auto& b=image_.bytes(); std::uint32_t v=0; for(unsigned i=0;i<4;++i)v|=static_cast<std::uint32_t>(b[o+i])<<(8*i); return v;
}
std::optional<std::uint64_t> BinaryView::u64le(std::size_t o) const noexcept {
 if(!contains(o,8)) return {}; const auto& b=image_.bytes(); std::uint64_t v=0; for(unsigned i=0;i<8;++i)v|=static_cast<std::uint64_t>(b[o+i])<<(8*i); return v;
}
}
