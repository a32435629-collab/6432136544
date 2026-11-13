#pragma once

#include "lulz/core/Result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz {

struct PESection {
    std::string name;
    std::uint32_t virtualSize = 0;
    std::uint32_t virtualAddress = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t characteristics = 0;
};

struct ImportSymbol {
    std::string module;
    std::string name;
    std::uint32_t iatRva = 0;
    bool byOrdinal = false;
    std::uint16_t ordinal = 0;
};

struct RuntimeFunctionEntry {
    std::uint32_t beginRva = 0;
    std::uint32_t endRva = 0;
    std::uint32_t unwindInfoRva = 0;
    std::size_t fileOffset = 0;
};

struct PEInfo {
    bool is64 = false;
    std::uint16_t machine = 0;
    std::uint16_t sectionCount = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t entryPoint = 0;
    std::uint64_t imageBase = 0;
    std::uint32_t imageBase32 = 0;

    std::uint32_t importDirectoryRva = 0;
    std::uint32_t importDirectorySize = 0;
    std::uint32_t exceptionDirectoryRva = 0;
    std::uint32_t exceptionDirectorySize = 0;

    std::vector<PESection> sections;
};

Result<PEInfo> parsePE(std::span<const std::uint8_t> bytes);

Result<std::vector<RuntimeFunctionEntry>> parsePEExceptionDirectory(
    std::span<const std::uint8_t> bytes,
    const PEInfo& info
);

Result<std::vector<ImportSymbol>> parsePEImports(
    std::span<const std::uint8_t> bytes,
    const PEInfo& info
);

} // namespace lulz