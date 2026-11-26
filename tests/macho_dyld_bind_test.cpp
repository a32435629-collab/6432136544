#include "binary/BinaryFormats.hpp"
#include "binary/BinaryImage.hpp"
#include <algorithm>
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
std::vector<std::uint8_t> makeImage(const std::vector<std::uint8_t>& stream, bool bind) {
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
    if (bind) {
        put32(b,dyld+16,0x1c0);
        put32(b,dyld+20,static_cast<std::uint32_t>(stream.size()));
    } else {
        put32(b,dyld+8,0x1c0);
        put32(b,dyld+12,static_cast<std::uint32_t>(stream.size()));
    }
    for(std::size_t i=0;i<stream.size();++i) b[0x1c0+i]=stream[i];
    return b;
}

std::vector<std::uint8_t> makeImageForStream(const std::vector<std::uint8_t>& stream, std::size_t streamIndex) {
    auto b = makeImage({}, false);
    const std::size_t dyld = 32 + 152 + 24;
    const std::size_t offsetField = dyld + 8 + streamIndex * 8;
    put32(b, offsetField, 0x1c0);
    put32(b, offsetField + 4, static_cast<std::uint32_t>(stream.size()));
    b.resize(0x1c0 + stream.size());
    for (std::size_t i = 0; i < stream.size(); ++i) b[0x1c0 + i] = stream[i];
    return b;
}

std::vector<std::uint8_t> makeChainedImage(bool bind = false) {
    std::vector<std::uint8_t> b(0x300);
    put32(b,0,0xfeedfacf); put32(b,4,0x01000007); put32(b,8,3); put32(b,12,2);
    put32(b,16,2); put32(b,20,168);
    const std::size_t seg=32;
    put32(b,seg,0x19); put32(b,seg+4,152);
    put64(b,seg+24,0x100000000ull); put64(b,seg+32,0x1000);
    put64(b,seg+40,0); put64(b,seg+48,0x300);
    put32(b,seg+56,7); put32(b,seg+60,5); put32(b,seg+64,0);
    const std::size_t fixcmd=seg+152;
    put32(b,fixcmd,0x80000034u); put32(b,fixcmd+4,16);
    put32(b,fixcmd+8,0x200);
    put32(b,fixcmd+12,bind ? 73 : 62);
    const std::size_t payload=0x200;
    put32(b,payload,0); put32(b,payload+4,28);
    put32(b,payload+8,bind ? 64 : 60);
    put32(b,payload+12,bind ? 68 : 60);
    put32(b,payload+16,bind ? 1 : 0);
    put32(b,payload+20,1); put32(b,payload+24,0);
    put32(b,payload+28,1); put32(b,payload+32,8);
    put32(b,payload+36,26);
    b[payload+40]=0x00; b[payload+41]=0x10; // page size 0x1000
    b[payload+42]=0x06; b[payload+43]=0x00; // DYLD_CHAINED_PTR_64_OFFSET
    put64(b,payload+44,0);
    put32(b,payload+52,0);
    b[payload+56]=1; b[payload+57]=0; // page_count=1
    b[payload+58]=0x80; b[payload+59]=0x00; // page start 0x80
    if (bind) {
        put32(b,payload+64,0); // lib ordinal 0, weak false, name offset 0
        b[payload+68]='_'; b[payload+69]='f'; b[payload+70]='o'; b[payload+71]='o'; b[payload+72]=0;
        put64(b,0x80,(std::uint64_t{1}<<63));
    } else {
        put64(b,0x80,0x1234);
    }
    return b;
}
std::vector<std::uint8_t> makeFatImage(const std::vector<std::uint8_t>& thin) {
    const std::size_t sliceOffset=0x1000;
    std::vector<std::uint8_t> b(sliceOffset+thin.size());
    b[0]=0xca; b[1]=0xfe; b[2]=0xba; b[3]=0xbe;
    b[7]=1; // nfat_arch = 1, big endian
    b[8]=0x01; b[9]=0x00; b[10]=0x00; b[11]=0x07; // CPU_TYPE_X86_64
    b[15]=0x03; // subtype 3
    b[16]=static_cast<std::uint8_t>((sliceOffset>>24)&0xff);
    b[17]=static_cast<std::uint8_t>((sliceOffset>>16)&0xff);
    b[18]=static_cast<std::uint8_t>((sliceOffset>>8)&0xff);
    b[19]=static_cast<std::uint8_t>(sliceOffset&0xff);
    const auto n=static_cast<std::uint32_t>(thin.size());
    b[20]=static_cast<std::uint8_t>(n>>24); b[21]=static_cast<std::uint8_t>(n>>16);
    b[22]=static_cast<std::uint8_t>(n>>8); b[23]=static_cast<std::uint8_t>(n);
    b[27]=12; // 2^12 alignment
    std::copy(thin.begin(),thin.end(),b.begin()+static_cast<std::ptrdiff_t>(sliceOffset));
    return b;
}

bool hasDiagnostic(const lulz::binary::FormatInfo& info, const char* code) {
    for(const auto& d:info.diagnostics.diagnostics) if(d.code==code) return true;
    return false;
}
}
int main() {
    using namespace lulz::binary;
    auto valid=analyzeFormat(BinaryImage::fromBytes(makeImage({0x11,0x20,0x80,0x01,0x51,0x00},false)));
    assert(valid.format==Format::MachO && valid.valid);
    assert(valid.rebases.size()==1);
    assert(valid.rebases[0].type==1 && valid.rebases[0].segmentIndex==0);
    assert(valid.rebases[0].segmentOffset==0x80);
    assert(valid.rebases[0].address==0x100000080ull);
    assert(valid.rebases[0].fileOffset==0x80);

    auto invalidOpcode=analyzeFormat(BinaryImage::fromBytes(makeImage({0x91,0x00},false)));
    assert(!invalidOpcode.valid && hasDiagnostic(invalidOpcode,"MACHO_REBASE_OPCODE"));

    auto invalidSegment=analyzeFormat(BinaryImage::fromBytes(makeImage({0x21,0x80,0x51,0x00},false)));
    assert(!invalidSegment.valid && hasDiagnostic(invalidSegment,"MACHO_REBASE_OPCODE"));

    auto noDone=analyzeFormat(BinaryImage::fromBytes(makeImage({0x11,0x20,0x80,0x51},false)));
    assert(!noDone.valid && hasDiagnostic(noDone,"MACHO_REBASE_UNTERMINATED"));

    auto badLocation=analyzeFormat(BinaryImage::fromBytes(makeImage({0x11,0x20,0xf9,0x01,0x51,0x00},false)));
    assert(!badLocation.valid && hasDiagnostic(badLocation,"MACHO_REBASE_OPCODE"));

    const std::vector<std::uint8_t> bindStream = {
        0x11,                   // dylib ordinal 1
        0x40, '_','f','o','o',0,// symbol
        0x60, 0x7f,             // addend -1
        0x70, 0x80, 0x01,       // segment 0, offset 128
        0x90,                   // bind
        0x00                    // done
    };
    auto bound=analyzeFormat(BinaryImage::fromBytes(makeImage(bindStream,true)));
    assert(bound.valid && bound.binds.size()==1);
    assert(bound.binds[0].symbolName=="_foo");
    assert(bound.binds[0].libraryOrdinal==1);
    assert(bound.binds[0].addend==-1);
    assert(bound.binds[0].segmentIndex==0 && bound.binds[0].segmentOffset==0x80);
    assert(bound.binds[0].address==0x100000080ull && bound.binds[0].fileOffset==0x80);

    auto badSymbol=analyzeFormat(BinaryImage::fromBytes(makeImage({0x40,'x','y'},true)));
    assert(!badSymbol.valid && hasDiagnostic(badSymbol,"MACHO_BIND_OPCODE"));

    auto badBindLocation=analyzeFormat(BinaryImage::fromBytes(makeImage({
        0x40,'_','x',0,0x70,0xf9,0x01,0x90,0x00
    },true)));
    assert(!badBindLocation.valid && hasDiagnostic(badBindLocation,"MACHO_BIND_OPCODE"));

    auto bindNoDone=analyzeFormat(BinaryImage::fromBytes(makeImage({
        0x40,'_','x',0,0x70,0x80,0x01,0x90
    },true)));
    assert(!bindNoDone.valid && hasDiagnostic(bindNoDone,"MACHO_BIND_UNTERMINATED"));

    // Minimal export trie: root -> "_foo" terminal, flags=0, address=0x80.
    auto exportImage = makeImage({}, false);
    put32(exportImage, 32 + 152 + 24 + 40, 0x1c0); // export_off (LC_DYLD_INFO field 8)
    put32(exportImage, 32 + 152 + 24 + 44, 7);    // export_size
    const std::uint8_t trie[] = {0x00, 0x01, '_','f','o','o',0x00, 0x08, 0x03, 0x00, 0x80, 0x01, 0x00};
    exportImage.resize(0x1c0 + sizeof(trie));
    for (std::size_t i = 0; i < sizeof(trie); ++i) exportImage[0x1c0 + i] = trie[i];
    // Correct the stream size to the complete trie.
    put32(exportImage, 32 + 152 + 24 + 44, sizeof(trie));
    auto exported = analyzeFormat(BinaryImage::fromBytes(exportImage));
    assert(exported.valid && exported.exports.size() == 1);
    assert(exported.exports[0].name == "_foo");
    assert(exported.exports[0].address == 0x80);

    auto malformedTrie = exportImage;
    malformedTrie[0x1c0 + 7] = 0x7f;
    auto badExport = analyzeFormat(BinaryImage::fromBytes(malformedTrie));
    assert(!badExport.valid);
    assert(hasDiagnostic(badExport, "MACHO_EXPORT_CHILD_OFFSET") ||
           hasDiagnostic(badExport, "MACHO_EXPORT_NODE_OFFSET"));


    const std::vector<std::uint8_t> weakBindStream = {
        0x11, 0x40, '_','w','e','a','k',0, 0x70, 0x80, 0x01, 0x90, 0x00
    };
    auto weakBound = analyzeFormat(BinaryImage::fromBytes(makeImageForStream(weakBindStream, 2)));
    assert(weakBound.valid && weakBound.binds.size() == 1);
    assert(weakBound.binds[0].symbolName == "_weak");
    assert(weakBound.binds[0].streamKind == MachODyldStreamKind::WeakBind);
    auto badWeak = analyzeFormat(BinaryImage::fromBytes(makeImageForStream({0x40, '_','x',0, 0xe0, 0x00}, 2)));
    assert(!badWeak.valid && hasDiagnostic(badWeak, "MACHO_WEAK_BIND_OPCODE"));

    const std::vector<std::uint8_t> lazyBindStream = {
        0x11, 0x40, '_','f','i','r','s','t',0, 0x70, 0x80, 0x01, 0x90, 0x00,
        0x11, 0x40, '_','s','e','c','o','n','d',0, 0x70, 0x90, 0x01, 0x90, 0x00
    };
    auto lazyBound = analyzeFormat(BinaryImage::fromBytes(makeImageForStream(lazyBindStream, 3)));
    assert(lazyBound.valid && lazyBound.binds.size() == 2);
    assert(lazyBound.binds[0].symbolName == "_first");
    assert(lazyBound.binds[1].symbolName == "_second");
    assert(lazyBound.binds[0].streamKind == MachODyldStreamKind::LazyBind);
    assert(lazyBound.binds[1].segmentOffset == 0x90);
    auto badLazy = analyzeFormat(BinaryImage::fromBytes(makeImageForStream({
        0x11, 0x40, '_','x',0, 0x70, 0x80, 0x01, 0x90
    }, 3)));
    assert(!badLazy.valid && hasDiagnostic(badLazy, "MACHO_LAZY_BIND_UNTERMINATED"));


    auto chainedRebase = analyzeFormat(BinaryImage::fromBytes(makeChainedImage(false)));
    assert(chainedRebase.valid && chainedRebase.chainedFixups.size() == 1);
    assert(!chainedRebase.chainedFixups[0].bind);
    assert(chainedRebase.chainedFixups[0].target == 0x1234);
    assert(chainedRebase.chainedFixups[0].fileOffset == 0x80);

    auto chainedBind = analyzeFormat(BinaryImage::fromBytes(makeChainedImage(true)));
    assert(chainedBind.valid && chainedBind.chainedImports.size() == 1);
    assert(chainedBind.chainedFixups.size() == 1 && chainedBind.chainedFixups[0].bind);
    assert(chainedBind.chainedFixups[0].symbolName == "_foo");

    auto fat = analyzeFormat(BinaryImage::fromBytes(makeFatImage(makeImage({}, false))));
    assert(fat.valid && fat.format == Format::MachO);
    assert(fat.universalArchitectures.size() == 1 && fat.universalArchitectures[0].valid);
    auto unsupportedChained = makeChainedImage(false);
    unsupportedChained[0x200 + 42] = 0x03;
    auto unsupported = analyzeFormat(BinaryImage::fromBytes(unsupportedChained));
    assert(!unsupported.valid && hasDiagnostic(unsupported, "MACHO_CHAINED_POINTER_FORMAT"));

    auto malformedFat = makeFatImage(makeImage({}, false));
    malformedFat[19] = 0xff;
    auto badFat = analyzeFormat(BinaryImage::fromBytes(malformedFat));
    assert(!badFat.valid && hasDiagnostic(badFat, "MACHO_FAT_SLICE_RANGE"));

    return 0;
}
