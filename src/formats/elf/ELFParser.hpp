#pragma once

#include "lulz/core/Result.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz::elf {

enum class Class : std::uint8_t { Elf32 = 1, Elf64 = 2 };
enum class ByteOrder : std::uint8_t { LittleEndian = 1, BigEndian = 2 };

struct Header {
    Class elfClass = Class::Elf64;
    ByteOrder byteOrder = ByteOrder::LittleEndian;
    std::uint8_t osAbi = 0;
    std::uint8_t abiVersion = 0;
    std::uint16_t type = 0;
    std::uint16_t machine = 0;
    std::uint32_t version = 0;
    std::uint64_t entry = 0;
    std::uint64_t programHeaderOffset = 0;
    std::uint64_t sectionHeaderOffset = 0;
    std::uint32_t flags = 0;
    std::uint16_t headerSize = 0;
    std::uint16_t programHeaderEntrySize = 0;
    std::uint16_t programHeaderCount = 0;
    std::uint16_t sectionHeaderEntrySize = 0;
    std::uint16_t sectionHeaderCount = 0;
    std::uint16_t sectionNameStringTableIndex = 0;
};

struct ProgramHeader {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t virtualAddress = 0;
    std::uint64_t physicalAddress = 0;
    std::uint64_t fileSize = 0;
    std::uint64_t memorySize = 0;
    std::uint64_t alignment = 0;
};

struct SectionHeader {
    std::string name;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t address = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t alignment = 0;
    std::uint64_t entrySize = 0;
};

struct Image {
    Header header;
    std::vector<ProgramHeader> programHeaders;
    std::vector<SectionHeader> sectionHeaders;
    std::vector<std::string> neededLibraries;
    std::string interpreter;
    bool hasInterpreter = false;
};

// Parses ELF32/ELF64 files in either byte order. All file-backed ranges are
// checked before they are read. Extended ELF numbering is supported.
Result<Image> parse(std::span<const std::uint8_t> bytes);

} // namespace lulz::elf
