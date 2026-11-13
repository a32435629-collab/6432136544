#include "formats/elf/ELFParser.hpp"

#include <algorithm>
#include <limits>
#include <type_traits>
#include <utility>

namespace lulz::elf {
namespace {

constexpr std::uint32_t PT_INTERP = 3;
constexpr std::uint32_t SHT_STRTAB = 3;
constexpr std::uint32_t SHT_DYNAMIC = 6;
constexpr std::uint32_t SHT_NOBITS = 8;
constexpr std::uint64_t PN_XNUM = 0xffff;
constexpr std::uint64_t SHN_XINDEX = 0xffff;

bool rangeFits(std::size_t total, std::uint64_t offset, std::uint64_t size) {
    return offset <= total && size <= static_cast<std::uint64_t>(total) - offset;
}

template <typename T>
bool readInt(std::span<const std::uint8_t> bytes, std::uint64_t offset,
             ByteOrder order, T& value) {
    static_assert(std::is_unsigned_v<T>);
    if (!rangeFits(bytes.size(), offset, sizeof(T))) return false;
    value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        const auto shiftIndex = order == ByteOrder::LittleEndian ? i : sizeof(T) - 1 - i;
        value |= static_cast<T>(bytes[static_cast<std::size_t>(offset) + i])
                 << (shiftIndex * 8);
    }
    return true;
}

bool readString(std::span<const std::uint8_t> bytes, std::uint64_t offset,
                std::uint64_t size, std::uint64_t index, std::string& out) {
    if (index >= size || !rangeFits(bytes.size(), offset, size)) return false;
    const auto begin = static_cast<std::size_t>(offset + index);
    const auto endLimit = static_cast<std::size_t>(offset + size);
    auto end = begin;
    while (end < endLimit && bytes[end] != 0) ++end;
    if (end == endLimit) return false;
    out.assign(reinterpret_cast<const char*>(bytes.data() + begin), end - begin);
    return true;
}

struct RawSection {
    std::uint32_t name = 0;
    std::uint32_t type = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t flags = 0;
    std::uint64_t address = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint64_t alignment = 0;
    std::uint64_t entrySize = 0;
};

bool readSection(std::span<const std::uint8_t> bytes, std::uint64_t p,
                 bool is64, ByteOrder order, RawSection& s) {
    if (is64) {
        return readInt(bytes,p,order,s.name) && readInt(bytes,p+4,order,s.type) &&
            readInt(bytes,p+8,order,s.flags) && readInt(bytes,p+16,order,s.address) &&
            readInt(bytes,p+24,order,s.offset) && readInt(bytes,p+32,order,s.size) &&
            readInt(bytes,p+40,order,s.link) && readInt(bytes,p+44,order,s.info) &&
            readInt(bytes,p+48,order,s.alignment) && readInt(bytes,p+56,order,s.entrySize);
    }
    std::uint32_t flags=0,address=0,offset=0,size=0,alignment=0,entrySize=0;
    if (!readInt(bytes,p,order,s.name) || !readInt(bytes,p+4,order,s.type) ||
        !readInt(bytes,p+8,order,flags) || !readInt(bytes,p+12,order,address) ||
        !readInt(bytes,p+16,order,offset) || !readInt(bytes,p+20,order,size) ||
        !readInt(bytes,p+24,order,s.link) || !readInt(bytes,p+28,order,s.info) ||
        !readInt(bytes,p+32,order,alignment) || !readInt(bytes,p+36,order,entrySize))
        return false;
    s.flags=flags; s.address=address; s.offset=offset; s.size=size;
    s.alignment=alignment; s.entrySize=entrySize;
    return true;
}

} // namespace

Result<Image> parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 16)
        return Result<Image>::failure("ELF: truncated identification");
    if (bytes[0] != 0x7f || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F')
        return Result<Image>::failure("ELF: invalid magic");
    if ((bytes[4] != 1 && bytes[4] != 2) ||
        (bytes[5] != 1 && bytes[5] != 2) || bytes[6] != 1)
        return Result<Image>::failure("ELF: unsupported class, byte order, or identification version");

    const bool is64 = bytes[4] == 2;
    const ByteOrder order = bytes[5] == 1 ? ByteOrder::LittleEndian : ByteOrder::BigEndian;
    const std::uint16_t expectedHeaderSize = is64 ? 64 : 52;
    const std::uint16_t minProgramEntry = is64 ? 56 : 32;
    const std::uint16_t minSectionEntry = is64 ? 64 : 40;
    if (bytes.size() < expectedHeaderSize)
        return Result<Image>::failure("ELF: truncated file header");

    Image image;
    auto& h = image.header;
    h.elfClass = is64 ? Class::Elf64 : Class::Elf32;
    h.byteOrder = order;
    h.osAbi = bytes[7];
    h.abiVersion = bytes[8];

    if (!readInt(bytes,16,order,h.type) || !readInt(bytes,18,order,h.machine) ||
        !readInt(bytes,20,order,h.version))
        return Result<Image>::failure("ELF: invalid common header fields");

    if (is64) {
        if (!readInt(bytes,24,order,h.entry) ||
            !readInt(bytes,32,order,h.programHeaderOffset) ||
            !readInt(bytes,40,order,h.sectionHeaderOffset) ||
            !readInt(bytes,48,order,h.flags) || !readInt(bytes,52,order,h.headerSize) ||
            !readInt(bytes,54,order,h.programHeaderEntrySize) ||
            !readInt(bytes,56,order,h.programHeaderCount) ||
            !readInt(bytes,58,order,h.sectionHeaderEntrySize) ||
            !readInt(bytes,60,order,h.sectionHeaderCount) ||
            !readInt(bytes,62,order,h.sectionNameStringTableIndex))
            return Result<Image>::failure("ELF: truncated ELF64 header");
    } else {
        std::uint32_t entry=0, phoff=0, shoff=0;
        if (!readInt(bytes,24,order,entry) || !readInt(bytes,28,order,phoff) ||
            !readInt(bytes,32,order,shoff) || !readInt(bytes,36,order,h.flags) ||
            !readInt(bytes,40,order,h.headerSize) ||
            !readInt(bytes,42,order,h.programHeaderEntrySize) ||
            !readInt(bytes,44,order,h.programHeaderCount) ||
            !readInt(bytes,46,order,h.sectionHeaderEntrySize) ||
            !readInt(bytes,48,order,h.sectionHeaderCount) ||
            !readInt(bytes,50,order,h.sectionNameStringTableIndex))
            return Result<Image>::failure("ELF: truncated ELF32 header");
        h.entry=entry; h.programHeaderOffset=phoff; h.sectionHeaderOffset=shoff;
    }

    if (h.version != 1 || h.headerSize < expectedHeaderSize || h.headerSize > bytes.size())
        return Result<Image>::failure("ELF: invalid header version or size");

    // Extended numbering values are stored in section header zero.
    RawSection sectionZero{};
    const bool needsSectionZero = h.sectionHeaderOffset != 0 &&
        (h.sectionHeaderCount == 0 || h.sectionNameStringTableIndex == SHN_XINDEX ||
         h.programHeaderCount == PN_XNUM);
    if (needsSectionZero) {
        if (h.sectionHeaderEntrySize < minSectionEntry ||
            !rangeFits(bytes.size(),h.sectionHeaderOffset,h.sectionHeaderEntrySize) ||
            !readSection(bytes,h.sectionHeaderOffset,is64,order,sectionZero))
            return Result<Image>::failure("ELF: invalid section header zero");
        if (h.sectionHeaderCount == 0) {
            if (sectionZero.size > std::numeric_limits<std::uint16_t>::max())
                return Result<Image>::failure("ELF: extended section count is too large");
            h.sectionHeaderCount=static_cast<std::uint16_t>(sectionZero.size);
        }
        if (h.sectionNameStringTableIndex == SHN_XINDEX) {
            if (sectionZero.link > std::numeric_limits<std::uint16_t>::max())
                return Result<Image>::failure("ELF: extended string table index is too large");
            h.sectionNameStringTableIndex=static_cast<std::uint16_t>(sectionZero.link);
        }
        if (h.programHeaderCount == PN_XNUM) {
            if (sectionZero.info > std::numeric_limits<std::uint16_t>::max())
                return Result<Image>::failure("ELF: extended program header count is too large");
            h.programHeaderCount=static_cast<std::uint16_t>(sectionZero.info);
        }
    }

    if (h.programHeaderCount != 0) {
        if (h.programHeaderEntrySize < minProgramEntry)
            return Result<Image>::failure("ELF: program header entry is too small");
        const std::uint64_t tableSize =
            static_cast<std::uint64_t>(h.programHeaderEntrySize) * h.programHeaderCount;
        if (!rangeFits(bytes.size(),h.programHeaderOffset,tableSize))
            return Result<Image>::failure("ELF: program header table is out of bounds");

        for (std::uint32_t i=0; i<h.programHeaderCount; ++i) {
            const auto p=h.programHeaderOffset+static_cast<std::uint64_t>(i)*h.programHeaderEntrySize;
            ProgramHeader ph;
            if (is64) {
                if (!readInt(bytes,p,order,ph.type) || !readInt(bytes,p+4,order,ph.flags) ||
                    !readInt(bytes,p+8,order,ph.offset) || !readInt(bytes,p+16,order,ph.virtualAddress) ||
                    !readInt(bytes,p+24,order,ph.physicalAddress) || !readInt(bytes,p+32,order,ph.fileSize) ||
                    !readInt(bytes,p+40,order,ph.memorySize) || !readInt(bytes,p+48,order,ph.alignment))
                    return Result<Image>::failure("ELF: malformed ELF64 program header");
            } else {
                std::uint32_t off=0,va=0,pa=0,fs=0,ms=0,al=0;
                if (!readInt(bytes,p,order,ph.type) || !readInt(bytes,p+4,order,off) ||
                    !readInt(bytes,p+8,order,va) || !readInt(bytes,p+12,order,pa) ||
                    !readInt(bytes,p+16,order,fs) || !readInt(bytes,p+20,order,ms) ||
                    !readInt(bytes,p+24,order,ph.flags) || !readInt(bytes,p+28,order,al))
                    return Result<Image>::failure("ELF: malformed ELF32 program header");
                ph.offset=off; ph.virtualAddress=va; ph.physicalAddress=pa;
                ph.fileSize=fs; ph.memorySize=ms; ph.alignment=al;
            }
            if (ph.fileSize && !rangeFits(bytes.size(),ph.offset,ph.fileSize))
                return Result<Image>::failure("ELF: segment data is out of bounds");
            if (ph.type == PT_INTERP) {
                if (!ph.fileSize || !rangeFits(bytes.size(),ph.offset,ph.fileSize))
                    return Result<Image>::failure("ELF: invalid PT_INTERP segment");
                const auto begin=static_cast<std::size_t>(ph.offset);
                const auto end=begin+static_cast<std::size_t>(ph.fileSize);
                const auto nul=std::find(bytes.begin()+static_cast<std::ptrdiff_t>(begin),
                                         bytes.begin()+static_cast<std::ptrdiff_t>(end),0);
                if (nul == bytes.begin()+static_cast<std::ptrdiff_t>(end))
                    return Result<Image>::failure("ELF: unterminated interpreter path");
                image.interpreter.assign(reinterpret_cast<const char*>(bytes.data()+begin),
                    static_cast<std::size_t>(nul-(bytes.begin()+static_cast<std::ptrdiff_t>(begin))));
                image.hasInterpreter=true;
            }
            image.programHeaders.push_back(ph);
        }
    }

    std::vector<RawSection> rawSections;
    if (h.sectionHeaderCount != 0) {
        if (h.sectionHeaderEntrySize < minSectionEntry)
            return Result<Image>::failure("ELF: section header entry is too small");
        const std::uint64_t tableSize =
            static_cast<std::uint64_t>(h.sectionHeaderEntrySize) * h.sectionHeaderCount;
        if (!rangeFits(bytes.size(),h.sectionHeaderOffset,tableSize))
            return Result<Image>::failure("ELF: section header table is out of bounds");
        rawSections.reserve(h.sectionHeaderCount);
        for (std::uint32_t i=0; i<h.sectionHeaderCount; ++i) {
            RawSection s;
            const auto p=h.sectionHeaderOffset+static_cast<std::uint64_t>(i)*h.sectionHeaderEntrySize;
            if (!readSection(bytes,p,is64,order,s))
                return Result<Image>::failure("ELF: malformed section header");
            if (s.type != SHT_NOBITS && s.size && !rangeFits(bytes.size(),s.offset,s.size))
                return Result<Image>::failure("ELF: section contents are out of bounds");
            rawSections.push_back(s);
        }
    }

    std::uint64_t namesOffset=0, namesSize=0;
    if (h.sectionNameStringTableIndex != 0) {
        if (h.sectionNameStringTableIndex >= rawSections.size())
            return Result<Image>::failure("ELF: section-name string table index is invalid");
        const auto& names=rawSections[h.sectionNameStringTableIndex];
        if (names.type != SHT_STRTAB || !rangeFits(bytes.size(),names.offset,names.size))
            return Result<Image>::failure("ELF: invalid section-name string table");
        namesOffset=names.offset; namesSize=names.size;
    }

    for (const auto& s : rawSections) {
        SectionHeader out;
        if (namesSize && !readString(bytes,namesOffset,namesSize,s.name,out.name))
            return Result<Image>::failure("ELF: invalid section name");
        out.type=s.type; out.flags=s.flags; out.address=s.address; out.offset=s.offset;
        out.size=s.size; out.link=s.link; out.info=s.info;
        out.alignment=s.alignment; out.entrySize=s.entrySize;
        image.sectionHeaders.push_back(std::move(out));
    }

    // Resolve shared-library names from SHT_DYNAMIC entries and their linked string table.
    for (const auto& s : rawSections) {
        if (s.type != SHT_DYNAMIC) continue;
        if (s.link >= rawSections.size())
            return Result<Image>::failure("ELF: dynamic section has invalid string-table link");
        const auto& strings=rawSections[s.link];
        if (strings.type != SHT_STRTAB || !rangeFits(bytes.size(),strings.offset,strings.size))
            return Result<Image>::failure("ELF: dynamic section string table is invalid");
        const std::uint64_t minEntry=is64?16:8;
        const std::uint64_t entrySize=s.entrySize?s.entrySize:minEntry;
        if (entrySize<minEntry || s.size%entrySize!=0)
            return Result<Image>::failure("ELF: malformed dynamic section");

        for (std::uint64_t pos=0; pos<s.size; pos+=entrySize) {
            std::uint64_t tag=0,value=0;
            if (is64) {
                if (!readInt(bytes,s.offset+pos,order,tag) ||
                    !readInt(bytes,s.offset+pos+8,order,value))
                    return Result<Image>::failure("ELF: truncated dynamic entry");
            } else {
                std::uint32_t t=0,v=0;
                if (!readInt(bytes,s.offset+pos,order,t) ||
                    !readInt(bytes,s.offset+pos+4,order,v))
                    return Result<Image>::failure("ELF: truncated dynamic entry");
                tag=t; value=v;
            }
            if (tag==static_cast<std::uint64_t>(DT_NULL)) break;
            if (tag==static_cast<std::uint64_t>(DT_NEEDED)) {
                std::string library;
                if (!readString(bytes,strings.offset,strings.size,value,library))
                    return Result<Image>::failure("ELF: invalid DT_NEEDED string offset");
                image.neededLibraries.push_back(std::move(library));
            }
        }
    }

    return Result<Image>::success(std::move(image));
}

} // namespace lulz::elf
