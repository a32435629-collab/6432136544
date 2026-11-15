#pragma once

#include "lulz/formats/pe/PEParser.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz {

struct PEDataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    bool usesFileOffset = false;
    bool present() const { return rva != 0 && size != 0; }
};

struct PEExportSymbol {
    std::string name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
    bool forwarded = false;
    std::string forwarder;
};

struct PECertificateEntry {
    std::uint32_t length = 0;
    std::uint16_t revision = 0;
    std::uint16_t certificateType = 0;
    std::uint32_t fileOffset = 0;
};

struct PEBaseRelocation {
    std::uint32_t pageRva = 0;
    std::uint32_t targetRva = 0;
    std::uint8_t type = 0;
};

struct PETlsInfo {
    std::uint64_t startAddressOfRawData = 0;
    std::uint64_t endAddressOfRawData = 0;
    std::uint64_t addressOfIndex = 0;
    std::uint64_t addressOfCallbacks = 0;
    std::uint32_t sizeOfZeroFill = 0;
    std::uint32_t characteristics = 0;
    std::vector<std::uint32_t> callbackRvas;
};

struct PEDebugEntry {
    std::uint32_t timestamp = 0;
    std::uint32_t type = 0;
    std::uint32_t sizeOfData = 0;
    std::uint32_t addressOfRawData = 0;
    std::uint32_t pointerToRawData = 0;
};

struct PEExtendedInfo {
    PEInfo image;
    std::uint16_t characteristics = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dllCharacteristics = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::uint32_t checksum = 0;
    std::array<PEDataDirectory, 16> directories{};
    std::vector<PEExportSymbol> exports;
    std::vector<PEBaseRelocation> relocations;
    std::vector<PECertificateEntry> certificates;
    std::vector<PEDebugEntry> debugEntries;
    PETlsInfo tls;
    std::vector<std::string> warnings;
};

Result<PEExtendedInfo> parsePEExtended(std::span<const std::uint8_t> bytes);

} // namespace lulz
