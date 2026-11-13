#include "lulz/formats/FormatDetector.hpp"
namespace lulz {
std::string detectFormat(std::span<const std::uint8_t> b) {
    auto starts = [&](std::initializer_list<std::uint8_t> sig) {
        if (b.size()<sig.size()) return false;
        std::size_t i=0; for(auto x:sig) if(b[i++]!=x) return false; return true;
    };
    if (starts({'M','Z'})) return "PE/DOS executable candidate";
    if (starts({0x7f,'E','L','F'})) return "ELF";
    if (starts({0xfe,0xed,0xfa,0xce}) || starts({0xfe,0xed,0xfa,0xcf}) ||
        starts({0xcf,0xfa,0xed,0xfe}) || starts({0xca,0xfe,0xba,0xbe})) return "Mach-O / Universal binary";
    if (starts({'P','K',0x03,0x04})) return "ZIP";
    if (starts({0x1f,0x8b})) return "GZIP";
    if (starts({'S','Q','L','i','t','e'})) return "SQLite";
    return "Unknown / raw data";
}
}
