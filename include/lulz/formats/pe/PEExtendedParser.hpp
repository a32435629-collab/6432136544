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


struct PEBoundImport {
    std::string module;
    std::uint32_t timestamp = 0;
    std::uint16_t forwarderCount = 0;
};

struct PEResource {
    std::string path;
    std::uint32_t dataRva = 0;
    std::uint32_t size = 0;
    std::uint32_t codePage = 0;
    bool directory = false;
};

struct PELoadConfig {
    std::uint32_t declaredSize = 0;
    std::uint64_t securityCookieVa = 0;
    std::uint64_t guardCfCheckFunctionPointerVa = 0;
    std::uint64_t guardCfDispatchFunctionPointerVa = 0;
    std::uint64_t guardCfFunctionTableVa = 0;
    std::uint64_t guardCfFunctionCount = 0;
    std::uint32_t guardFlags = 0;
    std::vector<std::uint32_t> guardCfFunctionRvas;
};

struct PECodeViewInfo {
    bool rsds = false;
    std::string guid;
    std::uint32_t timestamp = 0;
    std::uint32_t age = 0;
    std::string pdbPath;
};

struct PEIATEntry {
    std::uint32_t rva = 0;
    std::uint64_t value = 0;
};

struct PEClrHeader {
    std::uint32_t headerSize = 0;
    std::uint16_t runtimeMajor = 0;
    std::uint16_t runtimeMinor = 0;
    std::uint32_t metadataRva = 0;
    std::uint32_t metadataSize = 0;
    std::uint32_t flags = 0;
    std::uint32_t entryPointTokenOrRva = 0;
    std::uint32_t resourcesRva = 0;
    std::uint32_t resourcesSize = 0;
    std::uint32_t strongNameSignatureRva = 0;
    std::uint32_t strongNameSignatureSize = 0;
};

struct PEWindowsMetadata {
    std::vector<PEBoundImport> boundImports;
    std::vector<PEResource> resources;
    PELoadConfig loadConfig;
    std::vector<PECodeViewInfo> codeView;
    std::vector<PEIATEntry> iat;
    PEClrHeader clr;
    std::vector<std::string> warnings;
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
    std::vector<ImportSymbol> delayImports;
    std::vector<PEBaseRelocation> relocations;
    std::vector<PECertificateEntry> certificates;
    std::vector<PEDebugEntry> debugEntries;
    PETlsInfo tls;
    PEWindowsMetadata windows;
    std::vector<std::string> warnings;
};

Result<PEExtendedInfo> parsePEExtended(std::span<const std::uint8_t> bytes);

Result<PEWindowsMetadata> parsePEWindowsMetadata(
    std::span<const std::uint8_t> bytes,
    const PEExtendedInfo& image
);

} // namespace lulz
