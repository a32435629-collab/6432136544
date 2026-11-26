#include "binary/BinaryFormats.hpp"
#include "binary/BinaryImage.hpp"
#include "binary/BinaryView.hpp"
#include "binary/BinaryValidation.hpp"

#include <cassert>
#include <cstdint>
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
    assert(view.u16le(0).value() == 0x1234);
    assert(view.u32le(0).value() == 0x56781234);
    assert(view.u64le(0).has_value());
    assert(!view.u64le(1).has_value());
    assert(img.contains(0,8) && !img.contains(1,8));
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

    auto elf = analyzeFormat(BinaryImage::fromBytes(makeElf64()));
    assert(elf.format == Format::ELF && elf.valid && elf.is64Bit);
    assert(elf.entryPoint == 0x400080 && elf.sections.size() == 1);
    assert(elf.sections[0].executable);

    auto badElfBytes = makeElf64();
    badElfBytes[4] = 0;
    auto badElf = analyzeFormat(BinaryImage::fromBytes(std::move(badElfBytes)));
    assert(badElf.format == Format::ELF && !badElf.valid);

    auto payloadImage = BinaryImage::fromBytes({0,0,'M','Z',0,0,0x50,0x4b,3,4,0x1f,0x8b,0,0});
    const auto payloads = detectEmbeddedPayloads(payloadImage);
    assert(payloads.size() == 3);
    assert(payloads[0].kind == "PE" && payloads[0].offset == 2);
}
