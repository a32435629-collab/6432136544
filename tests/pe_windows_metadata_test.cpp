#include "lulz/formats/pe/PEExtendedParser.hpp"
#include "lulz/formats/pe/PEWindowsMetadata.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    std::vector<std::uint8_t> pe(0xa00, 0);
    auto w16 = [&](std::size_t o, std::uint16_t v) {
        pe[o] = static_cast<std::uint8_t>(v);
        pe[o + 1] = static_cast<std::uint8_t>(v >> 8);
    };
    auto w32 = [&](std::size_t o, std::uint32_t v) {
        for (int n = 0; n < 4; ++n) pe[o + n] = static_cast<std::uint8_t>(v >> (n * 8));
    };
    auto w64 = [&](std::size_t o, std::uint64_t v) {
        for (int n = 0; n < 8; ++n) pe[o + n] = static_cast<std::uint8_t>(v >> (n * 8));
    };

    // Minimal PE32+ image with one .rdata section.
    w16(0, 0x5a4d); w32(0x3c, 0x80); w32(0x80, 0x00004550);
    w16(0x84, 0x8664); w16(0x86, 1); w16(0x94, 240); w16(0x98, 0x20b);
    w64(0x98 + 24, 0x140000000ull); // ImageBase
    w32(0x98 + 108, 16);
    const std::size_t section = 0x98 + 240;
    pe[section] = '.'; pe[section + 1] = 'r'; pe[section + 2] = 'd';
    pe[section + 3] = 'a'; pe[section + 4] = 't'; pe[section + 5] = 'a';
    w32(section + 8, 0x800); w32(section + 12, 0x1000);
    w32(section + 16, 0x800); w32(section + 20, 0x200);
    w32(section + 36, 0x40000040);

    const std::size_t dirs = 0x98 + 112;
    auto setDir = [&](std::size_t index, std::uint32_t rva, std::uint32_t size) {
        w32(dirs + index * 8, rva); w32(dirs + index * 8 + 4, size);
    };

    // 1. Bound import descriptor and its module-name string.
    setDir(11, 0x1000, 32);
    w32(0x200, 0x12345678); w16(0x204, 16); w16(0x206, 0);
    const char module[] = "KERNEL32.dll";
    for (std::size_t i = 0; i < sizeof(module); ++i) pe[0x210 + i] = module[i];

    // 2. Resource tree: RT_RCDATA (#10) -> resource ID 1 -> four-byte payload.
    setDir(2, 0x1040, 0x80);
    w16(0x24c, 0); w16(0x24e, 1);
    w32(0x250, 10); w32(0x254, 0x80000020);
    w16(0x26c, 0); w16(0x26e, 1);
    w32(0x270, 1); w32(0x274, 0x60);
    w32(0x2a0, 0x10f0); w32(0x2a4, 4); w32(0x2a8, 1200);
    pe[0x2f0] = 1; pe[0x2f1] = 2; pe[0x2f2] = 3; pe[0x2f3] = 4;

    // 3/4. Load config with security cookie and one Guard CF target.
    setDir(10, 0x1200, 0x98);
    w32(0x400, 0x98);
    w64(0x400 + 88, 0x140001350ull);
    w64(0x400 + 112, 0x140001360ull);
    w64(0x400 + 120, 0x140001368ull);
    w64(0x400 + 128, 0x140001380ull);
    w64(0x400 + 136, 1);
    w32(0x400 + 144, 0);
    w32(0x580, 0x1200);

    // 5. CodeView RSDS record referenced by IMAGE_DEBUG_DIRECTORY.
    setDir(6, 0x1100, 28);
    w32(0x300 + 12, 2); w32(0x300 + 16, 40); w32(0x300 + 24, 0x900);
    w32(0x900, 0x53445352);
    for (int i = 0; i < 16; ++i) pe[0x904 + i] = static_cast<std::uint8_t>(i);
    w32(0x914, 3);
    const char pdb[] = "C:\\symbols\\sample.pdb";
    for (std::size_t i = 0; i < sizeof(pdb); ++i) pe[0x918 + i] = pdb[i];
    w32(0x300 + 16, static_cast<std::uint32_t>(24 + sizeof(pdb)));

    // 6. IAT contains one pointer and a null slot.
    setDir(12, 0x1140, 16);
    w64(0x340, 0x123456789abcdef0ull); w64(0x348, 0);

    // 7. CLR header with mapped metadata, resources and strong-name ranges.
    setDir(14, 0x1180, 72);
    w32(0x380, 72); w16(0x384, 2); w16(0x386, 5);
    w32(0x388, 0x11d0); w32(0x38c, 16);
    w32(0x390, 1); w32(0x394, 0x06000001);
    w32(0x398, 0x11e0); w32(0x39c, 4);
    w32(0x3a0, 0x11f0); w32(0x3a4, 8);

    auto extended = lulz::parsePEExtended(pe);
    assert(extended);
    assert(extended.value().windows.boundImports.size() == 1);
    auto metadata = lulz::parsePEWindowsMetadata(pe, extended.value());
    assert(metadata);

    const auto& result = metadata.value();
    assert(result.boundImports.size() == 1);
    assert(result.boundImports[0].module == "KERNEL32.dll");
    assert(result.boundImports[0].timestamp == 0x12345678);

    bool foundResource = false;
    for (const auto& resource : result.resources) {
        if (!resource.directory && resource.path == "#10/#1") {
            foundResource = resource.dataRva == 0x10f0 &&
                resource.size == 4 && resource.codePage == 1200;
        }
    }
    assert(foundResource);

    assert(result.loadConfig.declaredSize == 0x98);
    assert(result.loadConfig.securityCookieVa == 0x140001350ull);
    assert(result.loadConfig.guardCfFunctionCount == 1);
    assert(result.loadConfig.guardCfFunctionRvas.size() == 1);
    assert(result.loadConfig.guardCfFunctionRvas[0] == 0x1200);

    assert(result.codeView.size() == 1);
    assert(result.codeView[0].rsds);
    assert(result.codeView[0].age == 3);
    assert(result.codeView[0].pdbPath == "C:\\symbols\\sample.pdb");
    assert(result.codeView[0].guid == "03020100-0504-0706-0809-0a0b0c0d0e0f");

    assert(result.iat.size() == 2);
    assert(result.iat[0].rva == 0x1140);
    assert(result.iat[0].value == 0x123456789abcdef0ull);
    assert(result.iat[1].value == 0);

    assert(result.clr.headerSize == 72);
    assert(result.clr.runtimeMajor == 2 && result.clr.runtimeMinor == 5);
    assert(result.clr.metadataRva == 0x11d0 && result.clr.metadataSize == 16);
    assert(result.clr.entryPointTokenOrRva == 0x06000001);
    assert(result.warnings.empty());

    // A malformed Guard CF table must be diagnosed without rejecting the PE.
    auto broken = pe;
    w64(0x400 + 128, 0x1400017ffull);
    auto brokenExtended = lulz::parsePEExtended(broken);
    assert(brokenExtended);
    auto brokenMetadata = lulz::parsePEWindowsMetadata(broken, brokenExtended.value());
    assert(brokenMetadata);
    bool guardRangeWarning = false;
    for (const auto& warning : brokenMetadata.value().warnings)
        guardRangeWarning = guardRangeWarning ||
            warning.find("Guard CF function table is outside section data") != std::string::npos;
    assert(guardRangeWarning);

    std::cout << "All PE Windows metadata tests passed\n";
}
