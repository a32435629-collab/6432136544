#pragma once
#include "lulz/core/Result.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace lulz::dotnet {
struct DataDirectory { std::uint32_t rva=0, size=0; };
struct ClrHeader {
 std::uint32_t headerSize=0; std::uint16_t runtimeMajor=0, runtimeMinor=0;
 DataDirectory metadata; std::uint32_t flags=0, entryPointToken=0;
 DataDirectory resources, strongNameSignature, codeManagerTable, vtableFixups,
  exportAddressTableJumps, managedNativeHeader;
};
struct MetadataStream { std::string name; std::uint32_t offset=0, size=0; };
struct TableCount { std::uint8_t tableId=0; std::uint32_t rows=0; };
struct Image {
 bool pe32Plus=false; std::uint16_t machine=0; std::uint32_t peEntryPointRva=0;
 ClrHeader clr; std::string metadataVersion;
 std::vector<MetadataStream> streams; std::vector<TableCount> tables;
 bool hasIlOnlyFlag=false, requires32Bit=false, isStrongNameSigned=false;
};
// Parses managed PE32/PE32+ images and validates the CLR metadata root.
Result<Image> parse(std::span<const std::uint8_t> bytes);
} // namespace lulz::dotnet
