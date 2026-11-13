#pragma once

#include "lulz/core/Result.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz::macho {

enum class ByteOrder { LittleEndian, BigEndian };

struct Header {
    bool is64Bit = false;
    ByteOrder byteOrder = ByteOrder::LittleEndian;
    std::uint32_t cpuType = 0;
    std::uint32_t cpuSubtype = 0;
    std::uint32_t fileType = 0;
    std::uint32_t commandCount = 0;
    std::uint32_t commandBytes = 0;
    std::uint32_t flags = 0;
};

struct Section {
    std::string name;
    std::string segmentName;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::uint32_t fileOffset = 0;
    std::uint32_t flags = 0;
};

struct Segment {
    std::string name;
    std::uint64_t vmAddress = 0;
    std::uint64_t vmSize = 0;
    std::uint64_t fileOffset = 0;
    std::uint64_t fileSize = 0;
    std::uint32_t maxProtection = 0;
    std::uint32_t initialProtection = 0;
    std::vector<Section> sections;
};

struct Dylib {
    std::string name;
    std::uint32_t timestamp = 0;
    std::uint32_t currentVersion = 0;
    std::uint32_t compatibilityVersion = 0;
};

struct Image {
    Header header;
    std::uint64_t entryPointFileOffset = 0;
    bool hasEntryPoint = false;
    std::vector<Segment> segments;
    std::vector<Dylib> dylibs;
    std::vector<std::uint32_t> loadCommandTypes;
};

// Parses thin 32-bit and 64-bit Mach-O images. Fat/universal containers are
// intentionally rejected; callers should select an architecture slice first.
Result<Image> parse(std::span<const std::uint8_t> bytes);

} // namespace lulz::macho
