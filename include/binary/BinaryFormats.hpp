#pragma once
#include "binary/BinaryImage.hpp"
#include "binary/BinaryView.hpp"
#include "binary/BinaryValidation.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace lulz::binary {
enum class Format { Unknown, PE, ELF, MachO };
struct Section { std::string name; std::uint64_t offset=0, size=0, address=0, virtualSize=0; bool executable=false; };
struct DataDirectory { std::uint32_t index=0; std::uint64_t address=0,size=0; };
struct EmbeddedPayload { std::string kind; std::uint64_t offset=0; };
struct Symbol { std::string name; std::uint8_t type=0; std::uint8_t section=0; std::uint16_t description=0; std::uint64_t value=0; };
struct Relocation { std::int32_t address=0; std::uint32_t symbolNumber=0; std::uint32_t value=0; std::uint8_t type=0; std::uint8_t length=0; bool pcRelative=false; bool external=false; bool scattered=false; };
struct FormatInfo { Format format=Format::Unknown; bool valid=false; bool is64Bit=false; std::uint64_t imageBase=0, entryPoint=0, entryFileOffset=0, entryStackSize=0; std::uint32_t architecture=0, architectureSubtype=0, fileType=0; std::vector<Section> sections; std::vector<DataDirectory> directories; std::vector<Symbol> symbols; std::vector<Relocation> relocations; ValidationReport diagnostics; };
FormatInfo analyzeFormat(const BinaryImage&);
std::optional<std::uint64_t> rvaToOffset(const FormatInfo&,std::uint64_t);
std::optional<std::uint64_t> offsetToRva(const FormatInfo&,std::uint64_t);
std::optional<std::uint64_t> vaToRva(const FormatInfo&,std::uint64_t);
std::vector<EmbeddedPayload> detectEmbeddedPayloads(const BinaryImage&);
}
