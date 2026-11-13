#include "formats/macho/MachOParser.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <string_view>

namespace lulz::macho {
namespace {

constexpr std::uint32_t MH_MAGIC = 0xfeedface;
constexpr std::uint32_t MH_MAGIC_64 = 0xfeedfacf;
constexpr std::uint32_t LC_SEGMENT = 0x1;
constexpr std::uint32_t LC_SYMTAB = 0x2;
constexpr std::uint32_t LC_LOAD_DYLIB = 0xc;
constexpr std::uint32_t LC_ID_DYLIB = 0xd;
constexpr std::uint32_t LC_LOAD_WEAK_DYLIB = 0x80000018;
constexpr std::uint32_t LC_REEXPORT_DYLIB = 0x8000001f;
constexpr std::uint32_t LC_LAZY_LOAD_DYLIB = 0x20;
constexpr std::uint32_t LC_LOAD_UPWARD_DYLIB = 0x80000023;
constexpr std::uint32_t LC_SEGMENT_64 = 0x19;
constexpr std::uint32_t LC_MAIN = 0x80000028;

bool rangeFits(std::size_t total, std::size_t offset, std::size_t length) {
    return offset <= total && length <= total - offset;
}

std::uint32_t read32(std::span<const std::uint8_t> b, std::size_t o, ByteOrder order) {
    if (order == ByteOrder::LittleEndian) {
        return std::uint32_t(b[o]) | (std::uint32_t(b[o + 1]) << 8) |
            (std::uint32_t(b[o + 2]) << 16) | (std::uint32_t(b[o + 3]) << 24);
    }
    return (std::uint32_t(b[o]) << 24) | (std::uint32_t(b[o + 1]) << 16) |
        (std::uint32_t(b[o + 2]) << 8) | std::uint32_t(b[o + 3]);
}

std::uint64_t read64(std::span<const std::uint8_t> b, std::size_t o, ByteOrder order) {
    const auto first = read32(b, o, order);
    const auto second = read32(b, o + 4, order);
    return order == ByteOrder::LittleEndian
        ? std::uint64_t(first) | (std::uint64_t(second) << 32)
        : (std::uint64_t(first) << 32) | std::uint64_t(second);
}

std::string fixedName(std::span<const std::uint8_t> b, std::size_t o, std::size_t n) {
    std::size_t length = 0;
    while (length < n && b[o + length] != 0) ++length;
    return std::string(reinterpret_cast<const char*>(b.data() + o), length);
}

bool isDylibCommand(std::uint32_t command) {
    return command == LC_LOAD_DYLIB || command == LC_ID_DYLIB ||
        command == LC_LOAD_WEAK_DYLIB || command == LC_REEXPORT_DYLIB ||
        command == LC_LAZY_LOAD_DYLIB || command == LC_LOAD_UPWARD_DYLIB;
}

Result<Segment> parseSegment(std::span<const std::uint8_t> b, std::size_t o,
                             std::uint32_t commandSize, const Header& h) {
    const bool is64 = h.is64Bit;
    const std::size_t fixedSize = is64 ? 72 : 56;
    const std::size_t sectionSize = is64 ? 80 : 68;
    if (commandSize < fixedSize)
        return Result<Segment>::failure("Mach-O segment command is too small");

    Segment segment;
    segment.name = fixedName(b, o + 8, 16);
    std::uint32_t sectionCount = 0;
    if (is64) {
        segment.vmAddress = read64(b, o + 24, h.byteOrder);
        segment.vmSize = read64(b, o + 32, h.byteOrder);
        segment.fileOffset = read64(b, o + 40, h.byteOrder);
        segment.fileSize = read64(b, o + 48, h.byteOrder);
        segment.maxProtection = read32(b, o + 56, h.byteOrder);
        segment.initialProtection = read32(b, o + 60, h.byteOrder);
        sectionCount = read32(b, o + 64, h.byteOrder);
    } else {
        segment.vmAddress = read32(b, o + 24, h.byteOrder);
        segment.vmSize = read32(b, o + 28, h.byteOrder);
        segment.fileOffset = read32(b, o + 32, h.byteOrder);
        segment.fileSize = read32(b, o + 36, h.byteOrder);
        segment.maxProtection = read32(b, o + 40, h.byteOrder);
        segment.initialProtection = read32(b, o + 44, h.byteOrder);
        sectionCount = read32(b, o + 48, h.byteOrder);
    }

    if (sectionCount > (commandSize - fixedSize) / sectionSize)
        return Result<Segment>::failure("Mach-O section table exceeds its load command");

    segment.sections.reserve(sectionCount);
    for (std::uint32_t i = 0; i < sectionCount; ++i) {
        const std::size_t s = o + fixedSize + std::size_t(i) * sectionSize;
        Section section;
        section.name = fixedName(b, s, 16);
        section.segmentName = fixedName(b, s + 16, 16);
        if (is64) {
            section.address = read64(b, s + 32, h.byteOrder);
            section.size = read64(b, s + 40, h.byteOrder);
            section.fileOffset = read32(b, s + 48, h.byteOrder);
            section.flags = read32(b, s + 64, h.byteOrder);
        } else {
            section.address = read32(b, s + 32, h.byteOrder);
            section.size = read32(b, s + 36, h.byteOrder);
            section.fileOffset = read32(b, s + 40, h.byteOrder);
            section.flags = read32(b, s + 56, h.byteOrder);
        }
        segment.sections.push_back(std::move(section));
    }
    return Result<Segment>::success(std::move(segment));
}

} // namespace

Result<Image> parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4)
        return Result<Image>::failure("File is too small for a Mach-O magic");

    const std::uint32_t littleMagic = std::uint32_t(bytes[0]) |
        (std::uint32_t(bytes[1]) << 8) | (std::uint32_t(bytes[2]) << 16) |
        (std::uint32_t(bytes[3]) << 24);

    Header header;
    if (littleMagic == MH_MAGIC) {
        header.is64Bit = false;
        header.byteOrder = ByteOrder::LittleEndian;
    } else if (littleMagic == MH_MAGIC_64) {
        header.is64Bit = true;
        header.byteOrder = ByteOrder::LittleEndian;
    } else if (littleMagic == 0xcefaedfe) {
        header.is64Bit = false;
        header.byteOrder = ByteOrder::BigEndian;
    } else if (littleMagic == 0xcffaedfe) {
        header.is64Bit = true;
        header.byteOrder = ByteOrder::BigEndian;
    } else {
        return Result<Image>::failure("Unsupported Mach-O magic (fat binaries are not supported)");
    }

    const std::size_t headerSize = header.is64Bit ? 32 : 28;
    if (!rangeFits(bytes.size(), 0, headerSize))
        return Result<Image>::failure("Truncated Mach-O header");

    header.cpuType = read32(bytes, 4, header.byteOrder);
    header.cpuSubtype = read32(bytes, 8, header.byteOrder);
    header.fileType = read32(bytes, 12, header.byteOrder);
    header.commandCount = read32(bytes, 16, header.byteOrder);
    header.commandBytes = read32(bytes, 20, header.byteOrder);
    header.flags = read32(bytes, 24, header.byteOrder);

    if (header.commandCount > header.commandBytes / 8)
        return Result<Image>::failure("Invalid Mach-O load command count");
    if (!rangeFits(bytes.size(), headerSize, header.commandBytes))
        return Result<Image>::failure("Mach-O load commands exceed file bounds");

    Image image;
    image.header = header;
    std::size_t offset = headerSize;
    const std::size_t commandsEnd = headerSize + header.commandBytes;

    for (std::uint32_t i = 0; i < header.commandCount; ++i) {
        if (!rangeFits(commandsEnd, offset, 8))
            return Result<Image>::failure("Truncated Mach-O load command header");

        const std::uint32_t command = read32(bytes, offset, header.byteOrder);
        const std::uint32_t commandSize = read32(bytes, offset + 4, header.byteOrder);
        if (commandSize < 8 || !rangeFits(commandsEnd, offset, commandSize))
            return Result<Image>::failure("Invalid Mach-O load command size");

        image.loadCommandTypes.push_back(command);

        if (command == LC_SEGMENT || command == LC_SEGMENT_64) {
            if ((command == LC_SEGMENT_64) != header.is64Bit)
                return Result<Image>::failure("Mach-O segment command bitness mismatch");
            auto segment = parseSegment(bytes, offset, commandSize, header);
            if (!segment) return Result<Image>::failure(segment.error());
            image.segments.push_back(std::move(segment.value()));
        } else if (isDylibCommand(command)) {
            if (commandSize < 24)
                return Result<Image>::failure("Mach-O dylib command is too small");
            const std::uint32_t nameOffset = read32(bytes, offset + 8, header.byteOrder);
            if (nameOffset < 24 || nameOffset >= commandSize)
                return Result<Image>::failure("Invalid Mach-O dylib name offset");
            const std::size_t nameStart = offset + nameOffset;
            const std::size_t commandEnd = offset + commandSize;
            std::size_t nameEnd = nameStart;
            while (nameEnd < commandEnd && bytes[nameEnd] != 0) ++nameEnd;
            if (nameEnd == commandEnd)
                return Result<Image>::failure("Unterminated Mach-O dylib name");
            image.dylibs.push_back({
                std::string(reinterpret_cast<const char*>(bytes.data() + nameStart), nameEnd - nameStart),
                read32(bytes, offset + 12, header.byteOrder),
                read32(bytes, offset + 16, header.byteOrder),
                read32(bytes, offset + 20, header.byteOrder)
            });
        } else if (command == LC_MAIN) {
            if (commandSize < 24)
                return Result<Image>::failure("Mach-O LC_MAIN command is too small");
            image.entryPointFileOffset = read64(bytes, offset + 8, header.byteOrder);
            image.hasEntryPoint = true;
        }

        offset += commandSize;
    }

    if (offset != commandsEnd)
        return Result<Image>::failure("Mach-O load command sizes do not match sizeofcmds");

    return Result<Image>::success(std::move(image));
}

} // namespace lulz::macho
