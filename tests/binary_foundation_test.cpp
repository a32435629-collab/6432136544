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
}
