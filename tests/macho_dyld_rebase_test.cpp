#include "binary/BinaryFormats.hpp"
#include "binary/BinaryImage.hpp"
#include <cassert>
#include <cstdint>
#include <vector>

namespace {
void put32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
    for (unsigned i=0;i<4;++i) b[o+i]=static_cast<std::uint8_t>(v>>(8*i));
}
void put64(std::vector<std::uint8_t>& b, std::size_t o, std::uint64_t v) {
    for (unsigned i=0;i<8;++i) b[o+i]=static_cast<std::uint8_t>(v>>(8*i));
}
std::vector<std::uint8_t> makeImage(const std::vector<std::uint8_t>& stream) {
    std::vector<std::uint8_t> b(0x200);
    put32(b,0,0xfeedfacf); put32(b,4,0x01000007); put32(b,8,3); put32(b,12,2);
    put32(b,16,3); put32(b,20,224);
    const std::size_t seg=32;
    put32(b,seg,0x19); put32(b,seg+4,152);
    put64(b,seg+24,0x100000000ull); put64(b,seg+32,0x1000);
    put64(b,seg+40,0); put64(b,seg+48,0x100);
    put32(b,seg+56,7); put32(b,seg+60,5); put32(b,seg+64,1);
    const std::size_t main=seg+152;
    put32(b,main,0x80000028u); put32(b,main+4,24); put64(b,main+8,0x80);
    const std::size_t dyld=main+24;
    put32(b,dyld,0x22); put32(b,dyld+4,48);
    put32(b,dyld+8,0x1c0); put32(b,dyld+12,static_cast<std::uint32_t>(stream.size()));
    for(std::size_t i=0;i<stream.size();++i) b[0x1c0+i]=stream[i];
    return b;
}
bool hasDiagnostic(const lulz::binary::FormatInfo& info, const char* code) {
    for(const auto& d:info.diagnostics.diagnostics) if(d.code==code) return true;
    return false;
}
}
int main() {
    using namespace lulz::binary;
    auto valid=analyzeFormat(BinaryImage::fromBytes(makeImage({0x11,0x20,0x80,0x51,0x00})));
    assert(valid.format==Format::MachO && valid.valid);
    assert(valid.rebases.size()==1);
    assert(valid.rebases[0].type==1 && valid.rebases[0].segmentIndex==0);
    assert(valid.rebases[0].segmentOffset==0x80);
    assert(valid.rebases[0].address==0x100000080ull);
    assert(valid.rebases[0].fileOffset==0x80);

    auto invalidOpcode=analyzeFormat(BinaryImage::fromBytes(makeImage({0x91,0x00})));
    assert(!invalidOpcode.valid && hasDiagnostic(invalidOpcode,"MACHO_REBASE_OPCODE"));

    auto invalidSegment=analyzeFormat(BinaryImage::fromBytes(makeImage({0x21,0x80,0x51,0x00})));
    assert(!invalidSegment.valid && hasDiagnostic(invalidSegment,"MACHO_REBASE_OPCODE"));

    auto noDone=analyzeFormat(BinaryImage::fromBytes(makeImage({0x11,0x20,0x80,0x51})));
    assert(!noDone.valid && hasDiagnostic(noDone,"MACHO_REBASE_UNTERMINATED"));

    auto badLocation=analyzeFormat(BinaryImage::fromBytes(makeImage({0x11,0x20,0xf8,0x51,0x00})));
    assert(!badLocation.valid && hasDiagnostic(badLocation,"MACHO_REBASE_OPCODE"));
    return 0;
}
