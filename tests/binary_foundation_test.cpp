#include "binary/BinaryFormats.hpp"
#include "binary/BinaryImage.hpp"
#include "binary/BinaryView.hpp"
#include "binary/BinaryValidation.hpp"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace {
void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
    b[o] = static_cast<std::uint8_t>(v); b[o + 1] = static_cast<std::uint8_t>(v >> 8);
}
void put32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b[o + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put64(std::vector<std::uint8_t>& b, std::size_t o, std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) b[o + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
std::vector<std::uint8_t> makePe(bool badRawRange = false) {
    std::vector<std::uint8_t> b(0x400);
    b[0] = 'M'; b[1] = 'Z'; put32(b, 0x3c, 0x80);
    b[0x80] = 'P'; b[0x81] = 'E';
    put16(b, 0x84, 0x8664); put16(b, 0x86, 1); put16(b, 0x94, 240);
    const std::size_t o = 0x98;
    put16(b, o, 0x20b); put32(b, o + 16, 0x1000); put64(b, o + 24, 0x140000000ull);
    put32(b, o + 108, 16);
    const std::size_t s = o + 240;
    b[s] = '.'; b[s + 1] = 't'; b[s + 2] = 'e'; b[s + 3] = 'x'; b[s + 4] = 't';
    put32(b, s + 8, 0x100); put32(b, s + 12, 0x1000);
    put32(b, s + 16, 0x100); put32(b, s + 20, badRawRange ? 0x500 : 0x200);
    put32(b, s + 36, 0x60000020);
    return b;
}
std::vector<std::uint8_t> makeMachO64() {
    std::vector<std::uint8_t> b(0x200);
    put32(b, 0, 0xfeedfacf);
    put32(b, 4, 0x01000007); // CPU_TYPE_X86_64
    put32(b, 8, 3);
    put32(b, 12, 2); // MH_EXECUTE
    put32(b, 16, 2);
    put32(b, 20, 176);
    const std::size_t c = 32;
    put32(b, c, 0x19); // LC_SEGMENT_64
    put32(b, c + 4, 152);
    b[c + 8] = '_'; b[c + 9] = '_'; b[c + 10] = 'T'; b[c + 11] = 'E';
    b[c + 12] = 'X'; b[c + 13] = 'T';
    put64(b, c + 24, 0x100000000ull);
    put64(b, c + 32, 0x1000);
    put64(b, c + 40, 0);
    put64(b, c + 48, 0x100);
    put32(b, c + 56, 7);
    put32(b, c + 60, 5);
    put32(b, c + 64, 1);
    const std::size_t main = c + 152;
    put32(b, main, 0x80000028u); // LC_MAIN
    put32(b, main + 4, 24);
    put64(b, main + 8, 0x80); // entryoff within executable __TEXT
    put64(b, main + 16, 0x4000); // stacksize
    return b;
}
std::vector<std::uint8_t> makeMachO64WithSymtab() {
    auto b = makeMachO64();
    put32(b, 16, 3); // segment + LC_MAIN + LC_SYMTAB
    put32(b, 20, 200);
    const std::size_t symtab = 32 + 152 + 24;
    put32(b, symtab, 0x2); // LC_SYMTAB
    put32(b, symtab + 4, 24);
    put32(b, symtab + 8, 0x180); // symoff
    put32(b, symtab + 12, 1); // nsyms
    put32(b, symtab + 16, 0x190); // stroff
    put32(b, symtab + 20, 8); // strsize
    put32(b, 0x180, 1); // n_strx
    b[0x184] = 0x0f; // N_SECT | N_EXT
    b[0x185] = 1; // __TEXT section
    put16(b, 0x186, 0);
    put64(b, 0x188, 0x100000080ull);
    b[0x190] = 0;
    b[0x191] = 'f'; b[0x192] = 'o'; b[0x193] = 'o'; b[0x194] = 0;
    return b;
}
std::vector<std::uint8_t> makeMachO64WithRelocations() {
    auto b = makeMachO64WithSymtab();
    put32(b, 16, 4); // segment + LC_MAIN + LC_SYMTAB + LC_DYSYMTAB
    put32(b, 20, 280);
    const std::size_t dysymtab = 32 + 152 + 24 + 24;
    put32(b, dysymtab, 0xbu); // LC_DYSYMTAB
    put32(b, dysymtab + 4, 80);
    put32(b, dysymtab + 64, 0x1a0); // extreloff
    put32(b, dysymtab + 68, 1); // nextrel
    put32(b, 0x1a0, 0x80); // r_address
    put32(b, 0x1a4, 0x08000000u); // external, 8-byte, unsigned, symbol 0
    return b;
}
std::vector<std::uint8_t> makeMachO64WithIndirectSymbols() {
    auto b = makeMachO64WithSymtab();
    put32(b, 16, 4); // segment + LC_MAIN + LC_SYMTAB + LC_DYSYMTAB
    put32(b, 20, 280);
    const std::size_t dysymtab = 32 + 152 + 24 + 24;
    put32(b, dysymtab, 0xbu); // LC_DYSYMTAB
    put32(b, dysymtab + 4, 80);
    put32(b, dysymtab + 56, 0x1a0); // indirectsymoff
    put32(b, dysymtab + 60, 1); // nindirectsyms
    put32(b, 0x1a0, 0); // symbol index 0
    return b;
}
std::vector<std::uint8_t> makeMachO64WithTOC() {
    auto b = makeMachO64WithIndirectSymbols();
    const std::size_t dysymtab = 32 + 152 + 24 + 24;
    put32(b, dysymtab + 32, 0x1a8); // tocoff
    put32(b, dysymtab + 36, 1); // ntoc
    put32(b, dysymtab + 44, 1); // nmodtab
    put32(b, 0x1a8, 0); // module index
    put32(b, 0x1ac, 0); // symbol index
    return b;
}
std::vector<std::uint8_t> makeMachO64WithModuleTable() {
    auto b = makeMachO64WithTOC();
    const std::size_t dysymtab = 32 + 152 + 24 + 24;
    put32(b, dysymtab + 40, 0x1b0);
    put32(b, dysymtab + 44, 1);
    put32(b, 32 + 152 + 24 + 20, 12); // extend string table for module name
    put32(b, dysymtab + 52, 1);
    put32(b, dysymtab + 48, 0x1f0); // external reference table offset
    put32(b, 0x1f0, 1); // symbol index 0, reference flags 1
    put32(b, 0x1b0, 5);
    put32(b, 0x1b4, 0); put32(b, 0x1b8, 1);
    put32(b, 0x1bc, 0); put32(b, 0x1c0, 1);
    put32(b, 0x1c4, 0); put32(b, 0x1c8, 1);
    put32(b, 0x1cc, 0); put32(b, 0x1d0, 0);
    put32(b, 0x1d4, 0);
    put32(b, 0x1d8, 0);
    put64(b, 0x1e0, 0);
    b[0x195] = 'm'; b[0x196] = 'o'; b[0x197] = 'd'; b[0x198] = 0;
    return b;
}
std::vector<std::uint8_t> makeMachO64WithTwoLevelHints() {
    auto b = makeMachO64WithTOC();
    put32(b, 16, 5); // segment + LC_MAIN + LC_SYMTAB + LC_DYSYMTAB + LC_TWOLEVEL_HINTS
    put32(b, 20, 296);
    const std::size_t hints = 32 + 152 + 24 + 24 + 80;
    put32(b, hints, 0x16); // LC_TWOLEVEL_HINTS
    put32(b, hints + 4, 16);
    put32(b, hints + 8, 0x1b0);
    put32(b, hints + 12, 1);
    put32(b, 0x1b0, 0); // sub-image 0, TOC index 0
    return b;
}
std::vector<std::uint8_t> makeMachO64WithCodeSignature() {
    auto b = makeMachO64();
    put32(b, 16, 3);
    put32(b, 20, 192);
    const std::size_t signatureCommand = 32 + 152 + 24;
    put32(b, signatureCommand, 0x1d);
    put32(b, signatureCommand + 4, 16);
    put32(b, signatureCommand + 8, 0x1c0);
    put32(b, signatureCommand + 12, 36);
    put32(b, 0x1c0, 0xfade0cc0u);
    put32(b, 0x1c4, 36);
    put32(b, 0x1c8, 1);
    put32(b, 0x1cc, 0);
    put32(b, 0x1d0, 20);
    put32(b, 0x1d4, 0xfade0c02u);
    put32(b, 0x1d8, 16);
    return b;
}
std::vector<std::uint8_t> makeMachO64WithInitTermPointers() {
    auto b = makeMachO64();
    const std::size_t section = 32 + 72;
    b[section] = '_'; b[section + 1] = '_'; b[section + 2] = 'm'; b[section + 3] = 'o'; b[section + 4] = 'd'; b[section + 5] = '_'; b[section + 6] = 'i'; b[section + 7] = 'n'; b[section + 8] = 'i'; b[section + 9] = 't';
    put64(b, section + 32, 0x100000090ull);
    put64(b, section + 40, 8);
    put32(b, section + 48, 0x90);
    put32(b, section + 64, 0x9); // S_MOD_INIT_FUNC_POINTERS
    put64(b, 0x90, 0x100000080ull);
    return b;
}
std::vector<std::uint8_t> makeMachO64WithSectionRelocation() {
    auto b = makeMachO64WithSymtab();
    const std::size_t section = 32 + 72;
    put64(b, section + 40, 0x100); // section size for relocation-address validation
    put32(b, section + 56, 0x1a0); // section reloff
    put32(b, section + 60, 1); // section nreloc
    put32(b, 0x1a0, 0x80); // r_address within the section
    put32(b, 0x1a4, 0x08000000u); // external, 8-byte, unsigned, symbol 0
    return b;
}
std::vector<std::uint8_t> makeMachO64UnixThread() {
    auto b = makeMachO64();
    put32(b, 16, 2); // segment + LC_UNIXTHREAD
    put32(b, 20, 336);
    const std::size_t thread = 32 + 152;
    put32(b, thread, 0x5); // LC_UNIXTHREAD
    put32(b, thread + 4, 184);
    put32(b, thread + 8, 4); // x86_THREAD_STATE64
    put32(b, thread + 12, 42); // x86_THREAD_STATE64_COUNT
    put64(b, thread + 16 + 16 * 8, 0x100000080ull); // RIP
    return b;
}
std::vector<std::uint8_t> makeElf64() {
    std::vector<std::uint8_t> b(0x200);
    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2; b[5] = 1; b[6] = 1;
    put16(b, 16, 2); put16(b, 18, 62); put32(b, 20, 1);
    put64(b, 24, 0x400080); put64(b, 32, 64);
    put16(b, 52, 64); put16(b, 54, 56); put16(b, 56, 1);
    put32(b, 64, 1); put32(b, 68, 5); put64(b, 72, 0);
    put64(b, 80, 0x400000); put64(b, 96, 0x100); put64(b, 104, 0x200);
    return b;
}
}

int main() {
    using namespace lulz::binary;
    auto img = BinaryImage::fromBytes({0x34,0x12,0x78,0x56,0,0,0,0});
    BinaryView view(img);
    assert(view.u8(0).value() == 0x34);
    assert(view.u16le(0).value() == 0x1234);
    assert(view.u32le(0).value() == 0x56781234);
    assert(view.u32be(0).value() == 0x34127856);
    assert(view.u64le(0).has_value());
    assert(!view.u64le(1).has_value());
    assert(view.i16le(0).value() == 0x1234);
    assert(!view.i32be(6).has_value());
    assert(img.contains(0,8) && !img.contains(1,8));
    assert(view.bytes(2, 2)->size() == 2);
    assert(!view.bytes(7, 2).has_value());

    auto textImage = BinaryImage::fromBytes({'h','e','l','l','o',0,'x'});
    BinaryView textView(textImage);
    assert(textView.fixedString(0, 5).value() == "hello");
    assert(textView.cString(0, 7).value() == "hello");
    assert(!textView.cString(0, 5).has_value());
    assert(!textView.fixedString(6, 2).has_value());

    auto signedImage = BinaryImage::fromBytes({0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff});
    BinaryView signedView(signedImage);
    assert(signedView.i64le(0).value() == -1);
    assert(signedView.i64be(0).value() == -1);


    // File loader: bounded chunk reads, source tracking, empty files and limits.
    const auto loaderPath = std::filesystem::temp_directory_path() / "lulz_binary_loader_test.bin";
    {
        std::ofstream out(loaderPath, std::ios::binary | std::ios::trunc);
        const char contents[] = {char(0x41), char(0x00), char(0x42), char(0x43), char(0x44)};
        out.write(contents, sizeof(contents));
        assert(out.good());
    }
    BinaryLoadOptions loaderOptions;
    loaderOptions.maxBytes = 16;
    loaderOptions.chunkSize = 2;
    const auto loaded = BinaryImage::load(loaderPath, loaderOptions);
    assert(loaded.size() == 5 && loaded.source() == loaderPath.string());
    assert(loaded.bytes()[0] == 0x41 && loaded.bytes()[1] == 0x00 && loaded.bytes()[4] == 0x44);

    bool sizeLimitRejected = false;
    try {
        auto limited = loaderOptions;
        limited.maxBytes = 4;
        (void)BinaryImage::load(loaderPath, limited);
    } catch (const std::runtime_error&) { sizeLimitRejected = true; }
    assert(sizeLimitRejected);

    bool zeroChunkRejected = false;
    try {
        auto invalid = loaderOptions;
        invalid.chunkSize = 0;
        (void)BinaryImage::load(loaderPath, invalid);
    } catch (const std::invalid_argument&) { zeroChunkRejected = true; }
    assert(zeroChunkRejected);

    {
        std::ofstream out(loaderPath, std::ios::binary | std::ios::trunc);
        assert(out.good());
    }
    const auto emptyLoaded = BinaryImage::load(loaderPath, loaderOptions);
    assert(emptyLoaded.size() == 0);
    std::filesystem::remove(loaderPath);


    // Generic validation: limits, recognized truncated headers, and raw blobs.
    assert(validateImage(BinaryImage::fromBytes({0x7f, 'E', 'L'})).diagnostics[0].code ==
           "BIN_TRUNCATED_SIGNATURE");
    assert(!validateImage(BinaryImage::fromBytes({'M', 'Z'})).valid);
    assert(!validateImage(BinaryImage::fromBytes({0x7f, 'E', 'L', 'F', 2, 1, 1})).valid);
    ValidationOptions strictValidation;
    strictValidation.maxBytes = 4;
    assert(!validateImage(BinaryImage::fromBytes({1, 2, 3, 4, 5}), strictValidation).valid);
    assert(validateImage(BinaryImage::fromBytes({0xde, 0xad, 0xbe, 0xef})).valid);
    ValidationOptions signatureChecksOff;
    signatureChecksOff.validateKnownHeader = false;
    assert(validateImage(BinaryImage::fromBytes({'M', 'Z'}), signatureChecksOff).valid);

    assert(validateImage(img).valid);
    assert(!validateImage(BinaryImage::fromBytes({})).valid);

    auto pe = analyzeFormat(BinaryImage::fromBytes(makePe()));
    assert(pe.format == Format::PE && pe.valid && pe.is64Bit);
    assert(pe.sections.size() == 1 && pe.sections[0].executable);
    assert(pe.imageBase == 0x140000000ull && pe.entryPoint == 0x1000);
    assert(rvaToOffset(pe, 0x1010).value() == 0x210);
    assert(offsetToRva(pe, 0x210).value() == 0x1010);
    assert(vaToRva(pe, 0x140001000ull).value() == 0x1000);

    auto malformedPe = analyzeFormat(BinaryImage::fromBytes(makePe(true)));
    assert(malformedPe.format == Format::PE && !malformedPe.valid);
    assert(!malformedPe.diagnostics.diagnostics.empty());

    auto badDirectoryBytes = makePe();
    put32(badDirectoryBytes, 0x98 + 112, 0x9000); // export directory RVA
    put32(badDirectoryBytes, 0x98 + 116, 0x20);
    auto badDirectory = analyzeFormat(BinaryImage::fromBytes(std::move(badDirectoryBytes)));
    assert(badDirectory.format == Format::PE && !badDirectory.valid);
    bool foundUnmappedDirectory = false;
    for (const auto& diagnostic : badDirectory.diagnostics.diagnostics)
        if (diagnostic.code == "PE_DIRECTORY_UNMAPPED") foundUnmappedDirectory = true;
    assert(foundUnmappedDirectory);

    auto badEntryBytes = makePe();
    put32(badEntryBytes, 0x98 + 16, 0x9000);
    auto badEntry = analyzeFormat(BinaryImage::fromBytes(std::move(badEntryBytes)));
    assert(!badEntry.valid);

    auto elf = analyzeFormat(BinaryImage::fromBytes(makeElf64()));
    assert(elf.format == Format::ELF && elf.valid && elf.is64Bit);
    assert(elf.entryPoint == 0x400080 && elf.sections.size() == 1);
    assert(elf.sections[0].executable);

    auto badElfBytes = makeElf64();
    badElfBytes[4] = 0;
    auto badElf = analyzeFormat(BinaryImage::fromBytes(std::move(badElfBytes)));
    assert(badElf.format == Format::ELF && !badElf.valid);

    auto oversizedLoadBytes = makeElf64();
    put64(oversizedLoadBytes, 64 + 32, 0x300); // p_filesz > p_memsz
    auto oversizedLoad = analyzeFormat(BinaryImage::fromBytes(std::move(oversizedLoadBytes)));
    assert(!oversizedLoad.valid);

    auto invalidAlignBytes = makeElf64();
    put64(invalidAlignBytes, 64 + 48, 3); // p_align must be 0, 1, or a power of two
    auto invalidAlign = analyzeFormat(BinaryImage::fromBytes(std::move(invalidAlignBytes)));
    assert(!invalidAlign.valid);

    auto badElfEntryBytes = makeElf64();
    put64(badElfEntryBytes, 24, 0x500000); // outside executable PT_LOAD
    auto badElfEntry = analyzeFormat(BinaryImage::fromBytes(std::move(badElfEntryBytes)));
    assert(!badElfEntry.valid);

    auto badVirtualRangeBytes = makeElf64();
    put64(badVirtualRangeBytes, 64 + 16, 0xfffffffffffffff0ull);
    auto badVirtualRange = analyzeFormat(BinaryImage::fromBytes(std::move(badVirtualRangeBytes)));
    assert(!badVirtualRange.valid);


    auto macho = analyzeFormat(BinaryImage::fromBytes(makeMachO64()));
    assert(macho.format == Format::MachO && macho.valid && macho.is64Bit);
    assert(macho.architecture == 0x01000007 && macho.architectureSubtype == 3);
    assert(macho.fileType == 2 && macho.sections.size() == 1);
    assert(macho.sections[0].executable);
    assert(macho.entryFileOffset == 0x80 && macho.entryStackSize == 0x4000);
    assert(macho.entryPoint == 0x100000080ull);

    auto badMachOMainRangeBytes = makeMachO64();
    put64(badMachOMainRangeBytes, 32 + 152 + 8, 0x300);
    auto badMachOMainRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOMainRangeBytes)));
    assert(!badMachOMainRange.valid);

    auto badMachOMainSegmentBytes = makeMachO64();
    put64(badMachOMainSegmentBytes, 32 + 152 + 8, 0x180); // outside __TEXT file-backed range
    auto badMachOMainSegment = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOMainSegmentBytes)));
    assert(!badMachOMainSegment.valid);

    auto badMachOMainSizeBytes = makeMachO64();
    put32(badMachOMainSizeBytes, 32 + 152 + 4, 16);
    auto badMachOMainSize = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOMainSizeBytes)));
    assert(!badMachOMainSize.valid);

    auto duplicateMachOMainBytes = makeMachO64();
    duplicateMachOMainBytes.resize(0x200);
    put32(duplicateMachOMainBytes, 16, 3);
    put32(duplicateMachOMainBytes, 20, 200);
    const std::size_t duplicateMain = 32 + 152 + 24;
    put32(duplicateMachOMainBytes, duplicateMain, 0x80000028u);
    put32(duplicateMachOMainBytes, duplicateMain + 4, 24);
    put64(duplicateMachOMainBytes, duplicateMain + 8, 0x80);
    auto duplicateMachOMain = analyzeFormat(BinaryImage::fromBytes(std::move(duplicateMachOMainBytes)));
    assert(!duplicateMachOMain.valid);

    auto machoSymbols = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithSymtab()));
    assert(machoSymbols.format == Format::MachO && machoSymbols.valid);
    assert(machoSymbols.symbols.size() == 1);
    assert(machoSymbols.symbols[0].name == "foo");
    assert(machoSymbols.symbols[0].type == 0x0f && machoSymbols.symbols[0].section == 1);
    assert(machoSymbols.symbols[0].description == 0);
    assert(machoSymbols.symbols[0].value == 0x100000080ull);

    auto badMachOSymbolRangeBytes = makeMachO64WithSymtab();
    put32(badMachOSymbolRangeBytes, 32 + 152 + 24 + 8, 0x1f8);
    auto badMachOSymbolRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOSymbolRangeBytes)));
    assert(!badMachOSymbolRange.valid);

    auto badMachOStringRangeBytes = makeMachO64WithSymtab();
    put32(badMachOStringRangeBytes, 32 + 152 + 24 + 16, 0x1fc);
    auto badMachOStringRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOStringRangeBytes)));
    assert(!badMachOStringRange.valid);

    auto badMachOStringIndexBytes = makeMachO64WithSymtab();
    put32(badMachOStringIndexBytes, 0x180, 8);
    auto badMachOStringIndex = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOStringIndexBytes)));
    assert(!badMachOStringIndex.valid);

    auto unterminatedMachONameBytes = makeMachO64WithSymtab();
    for (std::size_t i = 0x191; i < 0x198; ++i) unterminatedMachONameBytes[i] = 'x';
    auto unterminatedMachOName = analyzeFormat(BinaryImage::fromBytes(std::move(unterminatedMachONameBytes)));
    assert(!unterminatedMachOName.valid);

    auto duplicateMachOSymtabBytes = makeMachO64WithSymtab();
    put32(duplicateMachOSymtabBytes, 16, 4);
    put32(duplicateMachOSymtabBytes, 20, 224);
    const std::size_t duplicateSymtab = 32 + 152 + 24 + 24;
    put32(duplicateMachOSymtabBytes, duplicateSymtab, 0x2);
    put32(duplicateMachOSymtabBytes, duplicateSymtab + 4, 24);
    put32(duplicateMachOSymtabBytes, duplicateSymtab + 8, 0x180);
    put32(duplicateMachOSymtabBytes, duplicateSymtab + 12, 1);
    put32(duplicateMachOSymtabBytes, duplicateSymtab + 16, 0x190);
    put32(duplicateMachOSymtabBytes, duplicateSymtab + 20, 8);
    auto duplicateMachOSymtab = analyzeFormat(BinaryImage::fromBytes(std::move(duplicateMachOSymtabBytes)));
    assert(!duplicateMachOSymtab.valid);

    auto machoRelocations = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithRelocations()));
    assert(machoRelocations.format == Format::MachO && machoRelocations.valid);
    assert(machoRelocations.relocations.size() == 1);
    assert(machoRelocations.relocations[0].address == 0x80);
    assert(machoRelocations.relocations[0].symbolNumber == 0);
    assert(machoRelocations.relocations[0].external);
    assert(machoRelocations.relocations[0].length == 3);
    assert(machoRelocations.relocations[0].type == 0);

    auto badMachORelocationRangeBytes = makeMachO64WithRelocations();
    put32(badMachORelocationRangeBytes, 32 + 152 + 24 + 24 + 64, 0x1fc);
    auto badMachORelocationRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachORelocationRangeBytes)));
    assert(!badMachORelocationRange.valid);

    auto badMachORelocationSymbolBytes = makeMachO64WithRelocations();
    put32(badMachORelocationSymbolBytes, 0x1a4, 0x08000001u);
    auto badMachORelocationSymbol = analyzeFormat(BinaryImage::fromBytes(std::move(badMachORelocationSymbolBytes)));
    assert(!badMachORelocationSymbol.valid);

    auto nonExternalMachORelocationBytes = makeMachO64WithRelocations();
    put32(nonExternalMachORelocationBytes, 0x1a4, 0x00000000u);
    auto nonExternalMachORelocation = analyzeFormat(BinaryImage::fromBytes(std::move(nonExternalMachORelocationBytes)));
    assert(!nonExternalMachORelocation.valid);

    auto machoDynamicSymbolRangesBytes = makeMachO64WithIndirectSymbols();
    const std::size_t dynamicSymbolCommand = 32 + 152 + 24 + 24;
    put32(machoDynamicSymbolRangesBytes, dynamicSymbolCommand + 8, 0); // local symbols
    put32(machoDynamicSymbolRangesBytes, dynamicSymbolCommand + 12, 0);
    put32(machoDynamicSymbolRangesBytes, dynamicSymbolCommand + 16, 0); // external definitions
    put32(machoDynamicSymbolRangesBytes, dynamicSymbolCommand + 20, 1);
    put32(machoDynamicSymbolRangesBytes, dynamicSymbolCommand + 24, 1); // undefined symbols
    put32(machoDynamicSymbolRangesBytes, dynamicSymbolCommand + 28, 0);
    auto machoDynamicSymbolRanges = analyzeFormat(BinaryImage::fromBytes(std::move(machoDynamicSymbolRangesBytes)));
    assert(machoDynamicSymbolRanges.valid);
    assert(machoDynamicSymbolRanges.externalSymbolIndex == 0);
    assert(machoDynamicSymbolRanges.externalSymbolCount == 1);
    assert(machoDynamicSymbolRanges.undefinedSymbolIndex == 1);

    auto badMachODynamicSymbolRangeBytes = makeMachO64WithIndirectSymbols();
    put32(badMachODynamicSymbolRangeBytes, dynamicSymbolCommand + 16, 1);
    put32(badMachODynamicSymbolRangeBytes, dynamicSymbolCommand + 20, 1);
    auto badMachODynamicSymbolRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachODynamicSymbolRangeBytes)));
    assert(!badMachODynamicSymbolRange.valid);
    bool foundDynamicSymbolRange = false;
    for (const auto& diagnostic : badMachODynamicSymbolRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_DYSYMTAB_EXTERNAL_SYMBOL_RANGE") foundDynamicSymbolRange = true;
    assert(foundDynamicSymbolRange);

    auto machoExternalReferences = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithModuleTable()));
    assert(machoExternalReferences.format == Format::MachO && machoExternalReferences.valid);
    assert(machoExternalReferences.externalReferences.size() == 1);
    assert(machoExternalReferences.externalReferences[0].symbolIndex == 0);
    assert(machoExternalReferences.externalReferences[0].flags == 1);

    auto badMachOExternalReferenceRangeBytes = makeMachO64WithModuleTable();
    const std::size_t externalReferenceDysymtab = 32 + 152 + 24 + 24;
    put32(badMachOExternalReferenceRangeBytes, externalReferenceDysymtab + 48, 0x1fc);
    auto badMachOExternalReferenceRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOExternalReferenceRangeBytes)));
    assert(!badMachOExternalReferenceRange.valid);
    bool foundExternalReferenceRange = false;
    for (const auto& diagnostic : badMachOExternalReferenceRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_EXTREFS_RANGE") foundExternalReferenceRange = true;
    assert(foundExternalReferenceRange);

    auto badMachOExternalReferenceSymbolBytes = makeMachO64WithModuleTable();
    put32(badMachOExternalReferenceSymbolBytes, 0x1f0, 0x00000101u); // symbol index 1 does not exist
    auto badMachOExternalReferenceSymbol = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOExternalReferenceSymbolBytes)));
    assert(!badMachOExternalReferenceSymbol.valid);
    bool foundExternalReferenceSymbol = false;
    for (const auto& diagnostic : badMachOExternalReferenceSymbol.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_EXTREFS_SYMBOL_INDEX") foundExternalReferenceSymbol = true;
    assert(foundExternalReferenceSymbol);

    auto machoModuleTable = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithModuleTable()));
    assert(machoModuleTable.format == Format::MachO && machoModuleTable.valid);
    assert(machoModuleTable.modules.size() == 1);
    assert(machoModuleTable.modules[0].name == "mod");
    assert(machoModuleTable.modules[0].externalSymbolCount == 1);
    assert(machoModuleTable.modules[0].referenceSymbolCount == 1);
    assert(machoModuleTable.modules[0].localSymbolCount == 1);

    auto badMachOModuleRangeBytes = makeMachO64WithModuleTable();
    const std::size_t moduleDysymtab = 32 + 152 + 24 + 24;
    put32(badMachOModuleRangeBytes, moduleDysymtab + 40, 0x1f0);
    auto badMachOModuleRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOModuleRangeBytes)));
    assert(!badMachOModuleRange.valid);
    bool foundModuleRange = false;
    for (const auto& diagnostic : badMachOModuleRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_DYSYMTAB_MODULE_RANGE") foundModuleRange = true;
    assert(foundModuleRange);

    auto badMachOModuleSymbolBytes = makeMachO64WithModuleTable();
    put32(badMachOModuleSymbolBytes, 0x1b8, 2);
    auto badMachOModuleSymbol = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOModuleSymbolBytes)));
    assert(!badMachOModuleSymbol.valid);

    auto badMachOModuleNameBytes = makeMachO64WithModuleTable();
    put32(badMachOModuleNameBytes, 0x1b0, 0xffffffffu);
    auto badMachOModuleName = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOModuleNameBytes)));
    assert(!badMachOModuleName.valid);

    auto machoTOC = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithTOC()));
    assert(machoTOC.format == Format::MachO && machoTOC.valid);
    assert(machoTOC.symbolTableOfContents.size() == 1);
    assert(machoTOC.symbolTableOfContents[0].moduleIndex == 0);
    assert(machoTOC.symbolTableOfContents[0].symbolIndex == 0);

    auto badMachOTocRangeBytes = makeMachO64WithTOC();
    const std::size_t tocDysymtab = 32 + 152 + 24 + 24;
    put32(badMachOTocRangeBytes, tocDysymtab + 32, 0x1fc);
    auto badMachOTocRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOTocRangeBytes)));
    assert(!badMachOTocRange.valid);
    bool foundTocRange = false;
    for (const auto& diagnostic : badMachOTocRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_DYSYMTAB_TOC_RANGE") foundTocRange = true;
    assert(foundTocRange);

    auto badMachOTocModuleBytes = makeMachO64WithTOC();
    put32(badMachOTocModuleBytes, 0x1a8, 1);
    auto badMachOTocModule = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOTocModuleBytes)));
    assert(!badMachOTocModule.valid);

    auto badMachOTocSymbolBytes = makeMachO64WithTOC();
    put32(badMachOTocSymbolBytes, 0x1ac, 1);
    auto badMachOTocSymbol = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOTocSymbolBytes)));
    assert(!badMachOTocSymbol.valid);

    auto machoIndirectSymbols = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithIndirectSymbols()));
    assert(machoIndirectSymbols.format == Format::MachO && machoIndirectSymbols.valid);
    assert(machoIndirectSymbols.indirectSymbols.size() == 1);
    assert(machoIndirectSymbols.indirectSymbols[0] == 0);

    auto badMachOIndirectRangeBytes = makeMachO64WithIndirectSymbols();
    put32(badMachOIndirectRangeBytes, 32 + 152 + 24 + 24 + 56, 0x1fc);
    auto badMachOIndirectRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOIndirectRangeBytes)));
    assert(!badMachOIndirectRange.valid);
    bool foundIndirectRange = false;
    for (const auto& diagnostic : badMachOIndirectRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_INDIRECT_SYMTAB_RANGE") foundIndirectRange = true;
    assert(foundIndirectRange);

    auto badMachOIndirectIndexBytes = makeMachO64WithIndirectSymbols();
    put32(badMachOIndirectIndexBytes, 0x1a0, 1);
    auto badMachOIndirectIndex = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOIndirectIndexBytes)));
    assert(!badMachOIndirectIndex.valid);

    auto machoLocalIndirectSymbolBytes = makeMachO64WithIndirectSymbols();
    put32(machoLocalIndirectSymbolBytes, 0x1a0, 0x80000000u);
    auto machoLocalIndirectSymbol = analyzeFormat(BinaryImage::fromBytes(std::move(machoLocalIndirectSymbolBytes)));
    assert(machoLocalIndirectSymbol.valid);
    assert(machoLocalIndirectSymbol.indirectSymbols[0] == 0x80000000u);

    auto machoTwoLevelHints = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithTwoLevelHints()));
    assert(machoTwoLevelHints.format == Format::MachO && machoTwoLevelHints.valid);
    assert(machoTwoLevelHints.twoLevelHints.size() == 1);
    assert(machoTwoLevelHints.twoLevelHints[0].subImage == 0);
    assert(machoTwoLevelHints.twoLevelHints[0].tableOfContentsIndex == 0);

    auto badMachOTwoLevelRangeBytes = makeMachO64WithTwoLevelHints();
    put32(badMachOTwoLevelRangeBytes, 32 + 152 + 24 + 24 + 80 + 8, 0x1ff);
    auto badMachOTwoLevelRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOTwoLevelRangeBytes)));
    assert(!badMachOTwoLevelRange.valid);
    bool foundTwoLevelRange = false;
    for (const auto& diagnostic : badMachOTwoLevelRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_TWOLEVEL_HINTS_RANGE") foundTwoLevelRange = true;
    assert(foundTwoLevelRange);

    auto badMachOTwoLevelTocBytes = makeMachO64WithTwoLevelHints();
    put32(badMachOTwoLevelTocBytes, 0x1b0, 1);
    auto badMachOTwoLevelToc = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOTwoLevelTocBytes)));
    assert(!badMachOTwoLevelToc.valid);
    bool foundTwoLevelToc = false;
    for (const auto& diagnostic : badMachOTwoLevelToc.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_TWOLEVEL_HINTS_TOC_INDEX") foundTwoLevelToc = true;
    assert(foundTwoLevelToc);

    auto machoCodeSignature = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithCodeSignature()));
    assert(machoCodeSignature.format == Format::MachO && machoCodeSignature.valid);
    assert(machoCodeSignature.codeSignatureOffset == 0x1c0);
    assert(machoCodeSignature.codeSignatureSize == 36);
    assert(machoCodeSignature.codeSignatureMagic == 0xfade0cc0u);
    assert(machoCodeSignature.codeSignatureBlobs.size() == 1);
    assert(machoCodeSignature.codeSignatureBlobs[0].slotType == 0);
    assert(machoCodeSignature.codeSignatureBlobs[0].magic == 0xfade0c02u);
    assert(machoCodeSignature.codeSignatureBlobs[0].length == 16);

    auto badMachOCodeSignatureRangeBytes = makeMachO64WithCodeSignature();
    put32(badMachOCodeSignatureRangeBytes, 32 + 152 + 24 + 8, 0x1f8);
    auto badMachOCodeSignatureRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOCodeSignatureRangeBytes)));
    assert(!badMachOCodeSignatureRange.valid);
    bool foundCodeSignatureRange = false;
    for (const auto& diagnostic : badMachOCodeSignatureRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_CODE_SIGNATURE_RANGE") foundCodeSignatureRange = true;
    assert(foundCodeSignatureRange);

    auto badMachOCodeSignatureBlobOffsetBytes = makeMachO64WithCodeSignature();
    put32(badMachOCodeSignatureBlobOffsetBytes, 0x1d0, 0xfffffff0u);
    auto badMachOCodeSignatureBlobOffset = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOCodeSignatureBlobOffsetBytes)));
    assert(!badMachOCodeSignatureBlobOffset.valid);
    bool foundCodeSignatureBlobOffset = false;
    for (const auto& diagnostic : badMachOCodeSignatureBlobOffset.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_CODE_SIGNATURE_BLOB_OFFSET") foundCodeSignatureBlobOffset = true;
    assert(foundCodeSignatureBlobOffset);

    auto badMachOCodeSignatureBlobRangeBytes = makeMachO64WithCodeSignature();
    put32(badMachOCodeSignatureBlobRangeBytes, 0x1d8, 0x40);
    auto badMachOCodeSignatureBlobRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOCodeSignatureBlobRangeBytes)));
    assert(!badMachOCodeSignatureBlobRange.valid);
    bool foundCodeSignatureBlobRange = false;
    for (const auto& diagnostic : badMachOCodeSignatureBlobRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_CODE_SIGNATURE_BLOB_RANGE") foundCodeSignatureBlobRange = true;
    assert(foundCodeSignatureBlobRange);

    auto machoInitTerm = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithInitTermPointers()));
    assert(machoInitTerm.format == Format::MachO && machoInitTerm.valid);
    assert(machoInitTerm.initTermPointers.size() == 1);
    assert(machoInitTerm.initTermPointers[0].initializer);
    assert(machoInitTerm.initTermPointers[0].address == 0x100000090ull);
    assert(machoInitTerm.initTermPointers[0].target == 0x100000080ull);

    auto badMachOInitTermSizeBytes = makeMachO64WithInitTermPointers();
    put64(badMachOInitTermSizeBytes, 32 + 72 + 40, 7);
    auto badMachOInitTermSize = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOInitTermSizeBytes)));
    assert(!badMachOInitTermSize.valid);
    bool foundInitTermSize = false;
    for (const auto& diagnostic : badMachOInitTermSize.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_INIT_TERM_SECTION_SIZE") foundInitTermSize = true;
    assert(foundInitTermSize);

    auto badMachOInitTermTargetBytes = makeMachO64WithInitTermPointers();
    put64(badMachOInitTermTargetBytes, 0x90, 0x200000000ull);
    auto badMachOInitTermTarget = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOInitTermTargetBytes)));
    assert(!badMachOInitTermTarget.valid);
    bool foundInitTermTarget = false;
    for (const auto& diagnostic : badMachOInitTermTarget.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_INIT_TERM_TARGET_NOT_EXECUTABLE") foundInitTermTarget = true;
    assert(foundInitTermTarget);

    auto machoSectionRelocation = analyzeFormat(BinaryImage::fromBytes(makeMachO64WithSectionRelocation()));
    assert(machoSectionRelocation.format == Format::MachO && machoSectionRelocation.valid);
    assert(machoSectionRelocation.relocations.size() == 1);
    assert(machoSectionRelocation.relocations[0].address == 0x80);
    assert(machoSectionRelocation.relocations[0].external);
    assert(machoSectionRelocation.relocations[0].symbolNumber == 0);

    auto badMachOSectionRelocRangeBytes = makeMachO64WithSectionRelocation();
    put32(badMachOSectionRelocRangeBytes, 32 + 72 + 56, 0x1fc);
    auto badMachOSectionRelocRange = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOSectionRelocRangeBytes)));
    assert(!badMachOSectionRelocRange.valid);
    bool foundSectionRelocRange = false;
    for (const auto& diagnostic : badMachOSectionRelocRange.diagnostics.diagnostics)
        if (diagnostic.code == "MACHO_SECTION_RELOC_RANGE") foundSectionRelocRange = true;
    assert(foundSectionRelocRange);

    auto badMachOSectionRelocAddressBytes = makeMachO64WithSectionRelocation();
    put32(badMachOSectionRelocAddressBytes, 0x1a0, 0x100); // outside section size
    auto badMachOSectionRelocAddress = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOSectionRelocAddressBytes)));
    assert(!badMachOSectionRelocAddress.valid);

    auto badMachOSectionRelocSymbolBytes = makeMachO64WithSectionRelocation();
    put32(badMachOSectionRelocSymbolBytes, 0x1a4, 0x08000001u);
    auto badMachOSectionRelocSymbol = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOSectionRelocSymbolBytes)));
    assert(!badMachOSectionRelocSymbol.valid);

    auto machoUnixThread = analyzeFormat(BinaryImage::fromBytes(makeMachO64UnixThread()));
    assert(machoUnixThread.format == Format::MachO && machoUnixThread.valid);
    assert(machoUnixThread.entryPoint == 0x100000080ull);

    auto badUnixThreadCountBytes = makeMachO64UnixThread();
    put32(badUnixThreadCountBytes, 32 + 152 + 12, 41);
    auto badUnixThreadCount = analyzeFormat(BinaryImage::fromBytes(std::move(badUnixThreadCountBytes)));
    assert(!badUnixThreadCount.valid);

    auto badUnixThreadRipBytes = makeMachO64UnixThread();
    put64(badUnixThreadRipBytes, 32 + 152 + 16 + 16 * 8, 0x200000000ull);
    auto badUnixThreadRip = analyzeFormat(BinaryImage::fromBytes(std::move(badUnixThreadRipBytes)));
    assert(!badUnixThreadRip.valid);

    auto duplicateUnixThreadBytes = makeMachO64UnixThread();
    duplicateUnixThreadBytes.resize(0x300);
    put32(duplicateUnixThreadBytes, 16, 3);
    put32(duplicateUnixThreadBytes, 20, 520);
    const std::size_t secondThread = 32 + 152 + 184;
    put32(duplicateUnixThreadBytes, secondThread, 0x5);
    put32(duplicateUnixThreadBytes, secondThread + 4, 184);
    put32(duplicateUnixThreadBytes, secondThread + 8, 4);
    put32(duplicateUnixThreadBytes, secondThread + 12, 42);
    put64(duplicateUnixThreadBytes, secondThread + 16 + 16 * 8, 0x100000080ull);
    auto duplicateUnixThread = analyzeFormat(BinaryImage::fromBytes(std::move(duplicateUnixThreadBytes)));
    assert(!duplicateUnixThread.valid);

    auto badMachOBytes = makeMachO64();
    put64(badMachOBytes, 32 + 32, 0xfffffffffffffff0ull);
    auto badMachO = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOBytes)));
    assert(!badMachO.valid);

    auto badMachOProtectionBytes = makeMachO64();
    put32(badMachOProtectionBytes, 32 + 60, 7); // exceeds max protection 7? change max below
    put32(badMachOProtectionBytes, 32 + 56, 1);
    auto badMachOProtection = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOProtectionBytes)));
    assert(!badMachOProtection.valid);

    auto badMachOSectionCountBytes = makeMachO64();
    put32(badMachOSectionCountBytes, 32 + 64, 2); // command only has room for one section
    auto badMachOSectionCount = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOSectionCountBytes)));
    assert(!badMachOSectionCount.valid);

    auto badMachOCmdSizeBytes = makeMachO64();
    put32(badMachOCmdSizeBytes, 32 + 4, 149);
    auto badMachOCmdSize = analyzeFormat(BinaryImage::fromBytes(std::move(badMachOCmdSizeBytes)));
    assert(!badMachOCmdSize.valid);

    auto payloadImage = BinaryImage::fromBytes({0,0,'M','Z',0,0,0x50,0x4b,3,4,0x1f,0x8b,0,0});
    const auto payloads = detectEmbeddedPayloads(payloadImage);
    assert(payloads.size() == 3);
    assert(payloads[0].kind == "PE" && payloads[0].offset == 2);

    auto expandedPayloadImage = BinaryImage::fromBytes({
        0,0,0x89,'P','N','G',0x0d,0x0a,0x1a,0x0a,
        '%','P','D','F','-','1','.','7',
        'G','I','F','8','9','a',
        0xfd,'7','z','X','Z',0x00
    });
    const auto expandedPayloads = detectEmbeddedPayloads(expandedPayloadImage);
    assert(expandedPayloads.size() >= 4);
    bool foundPng = false, foundPdf = false, foundGif = false, foundXz = false;
    for (const auto& payload : expandedPayloads) {
        foundPng |= payload.kind == "PNG";
        foundPdf |= payload.kind == "PDF";
        foundGif |= payload.kind == "GIF";
        foundXz |= payload.kind == "XZ";
    }
    assert(foundPng && foundPdf && foundGif && foundXz);
}
