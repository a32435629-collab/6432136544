#include "lulz/binary/BinaryWriter.hpp"
namespace lulz {
void BinaryWriter::u32le(std::uint32_t v) { for (unsigned i=0;i<4;++i) bytes_.push_back(static_cast<std::uint8_t>(v >> (8*i))); }
void BinaryWriter::append(const std::vector<std::uint8_t>& d) { bytes_.insert(bytes_.end(), d.begin(), d.end()); }
}
