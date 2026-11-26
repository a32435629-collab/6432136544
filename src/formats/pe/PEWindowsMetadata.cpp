#include "lulz/formats/pe/PEWindowsMetadata.hpp"
#include "lulz/binary/BinaryReader.hpp"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

namespace lulz {
namespace {

bool u16(const BinaryReader& r, std::size_t o, std::uint16_t& v) {
    auto x = r.u16le(o); if (!x) return false; v = x.value(); return true;
}
bool u32(const BinaryReader& r, std::size_t o, std::uint32_t& v) {
    auto x = r.u32le(o); if (!x) return false; v = x.value(); return true;
}
bool u64(const BinaryReader& r, std::size_t o, std::uint64_t& v) {
    auto x = r.u64le(o); if (!x) return false; v = x.value(); return true;
}

std::optional<std::size_t> mapRva(
    std::span<const std::uint8_t> bytes,
    const PEInfo& pe,
    std::uint32_t rva,
    std::size_t length
) {
    const std::uint64_t target = rva;
    for (const auto& section : pe.sections) {
        const std::uint64_t start = section.virtualAddress;
        if (target < start) continue;
        const std::uint64_t delta = target - start;
        const std::uint64_t span = std::max(section.virtualSize, section.rawSize);
        if (delta >= span) continue;
        if (delta >= section.rawSize ||
            length > std::uint64_t(section.rawSize) - delta) return std::nullopt;
        const std::uint64_t offset = std::uint64_t(section.rawOffset) + delta;
        if (offset > bytes.size() ||
            length > bytes.size() - static_cast<std::size_t>(offset)) return std::nullopt;
        return static_cast<std::size_t>(offset);
    }
    return std::nullopt;
}

std::optional<std::string> readCString(
    std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t limit
) {
    if (offset > bytes.size()) return std::nullopt;
    std::string value;
    const auto end = std::min(bytes.size(), offset + std::min(limit, bytes.size() - offset));
    for (std::size_t i = offset; i < end; ++i) {
        if (bytes[i] == 0) return value;
        value.push_back(static_cast<char>(bytes[i]));
    }
    return std::nullopt;
}

std::optional<std::string> readResourceName(
    const BinaryReader& reader,
    std::size_t root,
    std::uint32_t relative,
    std::size_t directorySize
) {
    if (relative > directorySize || directorySize - relative < 2) return std::nullopt;
    std::uint16_t length = 0;
    if (!u16(reader, root + relative, length)) return std::nullopt;
    if (length > 4096 || std::size_t(length) > (directorySize - relative - 2) / 2)
        return std::nullopt;
    std::string result;
    result.reserve(length);
    for (std::uint16_t i = 0; i < length; ++i) {
        std::uint16_t ch = 0;
        if (!u16(reader, root + relative + 2 + std::size_t(i) * 2, ch))
            return std::nullopt;
        result.push_back(ch >= 0x20 && ch <= 0x7e ? static_cast<char>(ch) : '?');
    }
    return result;
}

std::string guidString(const std::uint8_t* p) {
    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(2) << unsigned(p[3]) << std::setw(2) << unsigned(p[2])
        << std::setw(2) << unsigned(p[1]) << std::setw(2) << unsigned(p[0]) << '-'
        << std::setw(2) << unsigned(p[5]) << std::setw(2) << unsigned(p[4]) << '-'
        << std::setw(2) << unsigned(p[7]) << std::setw(2) << unsigned(p[6]) << '-'
        << std::setw(2) << unsigned(p[8]) << std::setw(2) << unsigned(p[9]) << '-';
    for (int i = 10; i < 16; ++i) out << std::setw(2) << unsigned(p[i]);
    return out.str();
}

void parseBoundImports(
    std::span<const std::uint8_t> bytes, const PEExtendedInfo& image,
    PEWindowsMetadata& out
) {
    const auto& dir = image.directories[11];
    if (!dir.present()) return;
    const auto base = mapRva(bytes, image.image, dir.rva, dir.size);
    if (!base) { out.warnings.emplace_back("bound import directory is outside section data"); return; }
    BinaryReader r(bytes);
    std::size_t cursor = 0;
    bool terminated = false;
    while (cursor + 8 <= dir.size && out.boundImports.size() < 65536) {
        std::uint32_t timestamp = 0;
        std::uint16_t nameOffset = 0, refs = 0;
        if (!u32(r, *base + cursor, timestamp) ||
            !u16(r, *base + cursor + 4, nameOffset) ||
            !u16(r, *base + cursor + 6, refs)) {
            out.warnings.emplace_back("truncated bound import descriptor"); return;
        }
        if (timestamp == 0 && nameOffset == 0 && refs == 0) { terminated = true; break; }
        if (nameOffset >= dir.size) {
            out.warnings.emplace_back("bound import module-name offset is outside directory"); return;
        }
        auto name = readCString(bytes, *base + nameOffset, dir.size - nameOffset);
        if (!name) { out.warnings.emplace_back("bound import module name is unterminated"); return; }
        out.boundImports.push_back({*name, timestamp, refs});
        const std::uint64_t next = std::uint64_t(cursor) + 8u + std::uint64_t(refs) * 8u;
        if (next > dir.size) {
            out.warnings.emplace_back("bound import forwarder references exceed directory"); return;
        }
        cursor = static_cast<std::size_t>(next);
    }
    if (!terminated) out.warnings.emplace_back("bound import descriptor table has no terminator or exceeds limit");
}

void parseResources(
    std::span<const std::uint8_t> bytes, const PEExtendedInfo& image,
    PEWindowsMetadata& out
) {
    const auto& dir = image.directories[2];
    if (!dir.present()) return;
    const auto base = mapRva(bytes, image.image, dir.rva, dir.size);
    if (!base) { out.warnings.emplace_back("resource directory is outside section data"); return; }
    BinaryReader r(bytes);
    std::size_t visited = 0;
    auto walk = [&](auto&& self, std::uint32_t rel, unsigned depth, const std::string& parent) -> void {
        if (depth > 16 || ++visited > 65536) {
            out.warnings.emplace_back("resource tree exceeds depth or entry safety limit"); return;
        }
        if (rel > dir.size || dir.size - rel < 16) {
            out.warnings.emplace_back("resource directory header is outside directory bounds"); return;
        }
        std::uint16_t named = 0, ids = 0;
        if (!u16(r, *base + rel + 12, named) || !u16(r, *base + rel + 14, ids)) {
            out.warnings.emplace_back("truncated resource directory header"); return;
        }
        const std::uint32_t count = std::uint32_t(named) + ids;
        if (count > 65536 || std::uint64_t(rel) + 16u + std::uint64_t(count) * 8u > dir.size) {
            out.warnings.emplace_back("resource directory entries exceed directory bounds"); return;
        }
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::size_t entry = *base + rel + 16 + std::size_t(i) * 8;
            std::uint32_t nameField = 0, target = 0;
            if (!u32(r, entry, nameField) || !u32(r, entry + 4, target)) {
                out.warnings.emplace_back("truncated resource directory entry"); return;
            }
            std::string component;
            if ((nameField & 0x80000000u) != 0) {
                auto name = readResourceName(r, *base, nameField & 0x7fffffffu, dir.size);
                if (!name) { out.warnings.emplace_back("invalid resource name string"); continue; }
                component = *name;
            } else {
                component = "#" + std::to_string(nameField & 0xffffu);
            }
            const std::string path = parent.empty() ? component : parent + "/" + component;
            if ((target & 0x80000000u) != 0) {
                PEResource item; item.path = path; item.directory = true;
                out.resources.push_back(std::move(item));
                self(self, target & 0x7fffffffu, depth + 1, path);
            } else {
                const std::uint32_t dataRel = target & 0x7fffffffu;
                if (dataRel > dir.size || dir.size - dataRel < 16) {
                    out.warnings.emplace_back("resource data entry is outside directory bounds"); continue;
                }
                std::uint32_t dataRva = 0, size = 0, codePage = 0;
                if (!u32(r, *base + dataRel, dataRva) ||
                    !u32(r, *base + dataRel + 4, size) ||
                    !u32(r, *base + dataRel + 8, codePage)) {
                    out.warnings.emplace_back("truncated resource data entry"); continue;
                }
                if (size != 0 && !mapRva(bytes, image.image, dataRva, size)) {
                    out.warnings.emplace_back("resource payload is outside mapped section data");
                }
                out.resources.push_back({path, dataRva, size, codePage, false});
            }
            if (out.resources.size() >= 65536) {
                out.warnings.emplace_back("resource count exceeds safety limit"); return;
            }
        }
    };
    walk(walk, 0, 0, {});
}

void parseLoadConfig(
    std::span<const std::uint8_t> bytes, const PEExtendedInfo& image,
    PEWindowsMetadata& out
) {
    const auto& dir = image.directories[10];
    if (!dir.present()) return;
    const auto header = mapRva(bytes, image.image, dir.rva, std::min<std::uint32_t>(dir.size, 4));
    if (!header) { out.warnings.emplace_back("load-config directory is outside section data"); return; }
    BinaryReader r(bytes);
    std::uint32_t declared = 0;
    if (!u32(r, *header, declared) || declared < 4) {
        out.warnings.emplace_back("invalid load-config declared size"); return;
    }
    const std::size_t available = std::min<std::size_t>(dir.size, declared);
    const auto base = mapRva(bytes, image.image, dir.rva, available);
    if (!base) { out.warnings.emplace_back("load-config declared range is outside section data"); return; }
    if (declared > dir.size) out.warnings.emplace_back("load-config declared size exceeds data-directory size");
    auto readPointer = [&](std::size_t offset, std::uint64_t& value) {
        if (offset > available || (image.image.is64 ? 8u : 4u) > available - offset) return false;
        if (image.image.is64) return u64(r, *base + offset, value);
        std::uint32_t v = 0; if (!u32(r, *base + offset, v)) return false; value = v; return true;
    };
    const std::size_t cookieOffset = image.image.is64 ? 88 : 60;
    const std::size_t checkOffset = image.image.is64 ? 112 : 72;
    const std::size_t dispatchOffset = image.image.is64 ? 120 : 76;
    const std::size_t tableOffset = image.image.is64 ? 128 : 80;
    const std::size_t countOffset = image.image.is64 ? 136 : 84;
    const std::size_t flagsOffset = image.image.is64 ? 144 : 88;
    auto& cfg = out.loadConfig;
    cfg.declaredSize = declared;
    readPointer(cookieOffset, cfg.securityCookieVa);
    readPointer(checkOffset, cfg.guardCfCheckFunctionPointerVa);
    readPointer(dispatchOffset, cfg.guardCfDispatchFunctionPointerVa);
    readPointer(tableOffset, cfg.guardCfFunctionTableVa);
    readPointer(countOffset, cfg.guardCfFunctionCount);
    if (flagsOffset <= available && available - flagsOffset >= 4)
        u32(r, *base + flagsOffset, cfg.guardFlags);

    if (cfg.guardCfFunctionCount == 0 || cfg.guardCfFunctionTableVa == 0) return;
    if (cfg.guardCfFunctionTableVa < image.image.imageBase ||
        cfg.guardCfFunctionTableVa - image.image.imageBase > 0xffffffffu) {
        out.warnings.emplace_back("Guard CF function table VA cannot be converted to an RVA"); return;
    }
    const auto tableRva = static_cast<std::uint32_t>(
        cfg.guardCfFunctionTableVa - image.image.imageBase);
    if (cfg.guardCfFunctionCount > 1'000'000) {
        out.warnings.emplace_back("Guard CF function count exceeds safety limit"); return;
    }
    const std::size_t stride = 4u + ((cfg.guardFlags >> 28) & 0x0fu);
    if (cfg.guardCfFunctionCount > std::numeric_limits<std::size_t>::max() / stride) {
        out.warnings.emplace_back("Guard CF function table size overflows"); return;
    }
    const auto table = mapRva(bytes, image.image, tableRva,
        static_cast<std::size_t>(cfg.guardCfFunctionCount) * stride);
    if (!table) { out.warnings.emplace_back("Guard CF function table is outside section data"); return; }
    for (std::uint64_t i = 0; i < cfg.guardCfFunctionCount; ++i) {
        std::uint32_t functionRva = 0;
        if (!u32(r, *table + static_cast<std::size_t>(i) * stride, functionRva)) break;
        cfg.guardCfFunctionRvas.push_back(functionRva);
        if (i != 0 && cfg.guardCfFunctionRvas[static_cast<std::size_t>(i - 1)] > functionRva)
            out.warnings.emplace_back("Guard CF function table is not sorted by RVA");
    }
}

void parseCodeView(
    std::span<const std::uint8_t> bytes, const PEExtendedInfo& image,
    PEWindowsMetadata& out
) {
    for (const auto& debug : image.debugEntries) {
        if (debug.type != 2 || debug.sizeOfData < 16) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
        const std::size_t offset = debug.pointerToRawData;
        if (offset > bytes.size() || debug.sizeOfData > bytes.size() - offset) {
            out.warnings.emplace_back("CodeView record is outside file bounds"); continue;
        }
        PECodeViewInfo record;
        const auto* p = bytes.data() + offset;
        const std::uint32_t signature = std::uint32_t(p[0]) |
            (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) |
            (std::uint32_t(p[3]) << 24);
        std::size_t pathOffset = 0;
        if (signature == 0x53445352u && debug.sizeOfData >= 24) { // RSDS
            record.rsds = true;
            record.guid = guidString(p + 4);
            record.age = std::uint32_t(p[20]) | (std::uint32_t(p[21]) << 8) |
                (std::uint32_t(p[22]) << 16) | (std::uint32_t(p[23]) << 24);
            pathOffset = 24;
        } else if (signature == 0x3031424eu && debug.sizeOfData >= 16) { // NB10
            record.rsds = false;
            record.timestamp = std::uint32_t(p[8]) | (std::uint32_t(p[9]) << 8) |
                (std::uint32_t(p[10]) << 16) | (std::uint32_t(p[11]) << 24);
            record.age = std::uint32_t(p[12]) | (std::uint32_t(p[13]) << 8) |
                (std::uint32_t(p[14]) << 16) | (std::uint32_t(p[15]) << 24);
            pathOffset = 16;
        } else {
            out.warnings.emplace_back("unsupported or truncated CodeView signature"); continue;
        }
        auto path = readCString(bytes, offset + pathOffset, debug.sizeOfData - pathOffset);
        if (!path) { out.warnings.emplace_back("CodeView PDB path is unterminated"); continue; }
        record.pdbPath = *path;
        out.codeView.push_back(std::move(record));
    }
}

void parseIat(
    std::span<const std::uint8_t> bytes, const PEExtendedInfo& image,
    PEWindowsMetadata& out
) {
    const auto& dir = image.directories[12];
    if (!dir.present()) return;
    const std::size_t pointerSize = image.image.is64 ? 8 : 4;
    if (dir.size % pointerSize != 0)
        out.warnings.emplace_back("IAT directory size is not pointer aligned");
    const auto count = dir.size / pointerSize;
    if (count > 1'000'000) { out.warnings.emplace_back("IAT entry count exceeds safety limit"); return; }
    const auto base = mapRva(bytes, image.image, dir.rva, count * pointerSize);
    if (!base) { out.warnings.emplace_back("IAT directory is outside section data"); return; }
    BinaryReader r(bytes);
    for (std::size_t i = 0; i < count; ++i) {
        std::uint64_t value = 0;
        if (image.image.is64) {
            if (!u64(r, *base + i * pointerSize, value)) break;
        } else {
            std::uint32_t v = 0; if (!u32(r, *base + i * pointerSize, v)) break; value = v;
        }
        out.iat.push_back({static_cast<std::uint32_t>(std::uint64_t(dir.rva) + i * pointerSize), value});
    }
}

void parseClr(
    std::span<const std::uint8_t> bytes, const PEExtendedInfo& image,
    PEWindowsMetadata& out
) {
    const auto& dir = image.directories[14];
    if (!dir.present()) return;
    if (dir.size < 72) { out.warnings.emplace_back("CLR runtime header is smaller than 72 bytes"); return; }
    const auto base = mapRva(bytes, image.image, dir.rva, 72);
    if (!base) { out.warnings.emplace_back("CLR runtime header is outside section data"); return; }
    BinaryReader r(bytes);
    auto& clr = out.clr;
    if (!u32(r, *base, clr.headerSize) ||
        !u16(r, *base + 4, clr.runtimeMajor) ||
        !u16(r, *base + 6, clr.runtimeMinor) ||
        !u32(r, *base + 8, clr.metadataRva) ||
        !u32(r, *base + 12, clr.metadataSize) ||
        !u32(r, *base + 16, clr.flags) ||
        !u32(r, *base + 20, clr.entryPointTokenOrRva) ||
        !u32(r, *base + 24, clr.resourcesRva) ||
        !u32(r, *base + 28, clr.resourcesSize) ||
        !u32(r, *base + 32, clr.strongNameSignatureRva) ||
        !u32(r, *base + 36, clr.strongNameSignatureSize)) {
        out.warnings.emplace_back("truncated CLR runtime header"); return;
    }
    if (clr.headerSize < 72 || clr.headerSize > dir.size)
        out.warnings.emplace_back("CLR runtime header declares an invalid size");
    auto checkRange = [&](std::uint32_t rva, std::uint32_t size, const char* label) {
        if (size != 0 && !mapRva(bytes, image.image, rva, size))
            out.warnings.emplace_back(std::string("CLR ") + label + " range is outside section data");
    };
    checkRange(clr.metadataRva, clr.metadataSize, "metadata");
    checkRange(clr.resourcesRva, clr.resourcesSize, "resources");
    checkRange(clr.strongNameSignatureRva, clr.strongNameSignatureSize, "strong-name signature");
}

} // namespace

Result<PEWindowsMetadata> parsePEWindowsMetadata(
    std::span<const std::uint8_t> bytes,
    const PEExtendedInfo& image
) {
    PEWindowsMetadata out;
    parseBoundImports(bytes, image, out);
    parseResources(bytes, image, out);
    parseLoadConfig(bytes, image, out);
    parseCodeView(bytes, image, out);
    parseIat(bytes, image, out);
    parseClr(bytes, image, out);
    return Result<PEWindowsMetadata>::success(std::move(out));
}

} // namespace lulz
