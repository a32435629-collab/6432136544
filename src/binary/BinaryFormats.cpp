#include "binary/BinaryFormats.hpp"

#include <algorithm>
#include <limits>

namespace lulz::binary {
namespace {

bool rangeFits(std::uint64_t offset, std::uint64_t length, std::size_t total) {
    return offset <= total && length <= static_cast<std::uint64_t>(total) - offset;
}

std::string name8(const BinaryImage& image, std::size_t offset) {
    std::string name;
    for (std::size_t i = 0; i < 8 && image.contains(offset + i, 1); ++i) {
        const auto ch = image.bytes()[offset + i];
        if (ch == 0) break;
        name.push_back(static_cast<char>(ch));
    }
    return name;
}

void diag(FormatInfo& info, const char* code, const char* message, std::size_t offset) {
    info.diagnostics.valid = false;
    info.diagnostics.diagnostics.push_back({code, message, offset});
}

void validateSections(FormatInfo& info, const BinaryImage& image) {
    for (std::size_t i = 0; i < info.sections.size(); ++i) {
        const auto& section = info.sections[i];
        if (!rangeFits(section.offset, section.size, image.size())) {
            diag(info, "SECTION_FILE_RANGE", "Section data extends beyond the file", static_cast<std::size_t>(std::min<std::uint64_t>(section.offset, image.size())));
        }
        if (section.virtualSize != 0 &&
            section.address > std::numeric_limits<std::uint64_t>::max() - section.virtualSize) {
            diag(info, "SECTION_VIRTUAL_OVERFLOW", "Section virtual address range overflows", 0);
        }
        for (std::size_t j = 0; j < i; ++j) {
            const auto& previous = info.sections[j];
            if (section.size && previous.size &&
                previous.offset <= std::numeric_limits<std::uint64_t>::max() - previous.size &&
                section.offset < previous.offset + previous.size) {
                diag(info, "SECTION_RAW_OVERLAP", "Section raw file ranges overlap", static_cast<std::size_t>(section.offset));
                break;
            }
        }
    }
}

} // namespace

FormatInfo analyzeFormat(const BinaryImage& image) {
    FormatInfo info;
    info.diagnostics = validateImage(image);
    BinaryView view(image);
    const auto& bytes = image.bytes();

    if (image.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
        info.format = Format::PE;
        const auto peOffsetValue = view.u32le(0x3c);
        if (!peOffsetValue) {
            diag(info, "PE_DOS_HEADER_TRUNCATED", "DOS header does not contain e_lfanew", 0x3c);
            return info;
        }
        const std::uint64_t peOffset = *peOffsetValue;
        if (!rangeFits(peOffset, 24, image.size()) ||
            bytes[static_cast<std::size_t>(peOffset)] != 'P' ||
            bytes[static_cast<std::size_t>(peOffset) + 1] != 'E' ||
            bytes[static_cast<std::size_t>(peOffset) + 2] != 0 ||
            bytes[static_cast<std::size_t>(peOffset) + 3] != 0) {
            diag(info, "PE_BAD_SIGNATURE", "Invalid or truncated PE signature/COFF header", static_cast<std::size_t>(std::min<std::uint64_t>(peOffset, image.size())));
            return info;
        }

        const std::size_t coff = static_cast<std::size_t>(peOffset) + 4;
        const auto sectionCount = view.u16le(coff + 2);
        const auto optionalSize = view.u16le(coff + 16);
        if (!sectionCount || !optionalSize) {
            diag(info, "PE_COFF_TRUNCATED", "COFF header is truncated", coff);
            return info;
        }
        const std::size_t optional = coff + 20;
        if (!image.contains(optional, *optionalSize) || *optionalSize < 2) {
            diag(info, "PE_OPTIONAL_TRUNCATED", "Optional header is truncated", optional);
            return info;
        }
        const auto magic = view.u16le(optional);
        if (!magic || (*magic != 0x10b && *magic != 0x20b)) {
            diag(info, "PE_BAD_OPTIONAL", "Unsupported PE optional-header magic", optional);
            return info;
        }
        info.is64Bit = *magic == 0x20b;
        const std::size_t minimum = info.is64Bit ? 112 : 96;
        if (*optionalSize < minimum) {
            diag(info, "PE_OPTIONAL_TOO_SMALL", "Optional header is too small for required fields", optional);
            return info;
        }
        const auto entry = view.u32le(optional + 16);
        if (!entry) {
            diag(info, "PE_ENTRYPOINT_TRUNCATED", "Entry point field is truncated", optional + 16);
            return info;
        }
        info.entryPoint = *entry;
        if (info.is64Bit) {
            const auto base = view.u64le(optional + 24);
            if (!base) { diag(info, "PE_IMAGE_BASE_TRUNCATED", "PE32+ image base is truncated", optional + 24); return info; }
            info.imageBase = *base;
        } else {
            const auto base = view.u32le(optional + 28);
            if (!base) { diag(info, "PE_IMAGE_BASE_TRUNCATED", "PE32 image base is truncated", optional + 28); return info; }
            info.imageBase = *base;
        }

        const std::size_t numberOffset = optional + (info.is64Bit ? 108 : 92);
        const std::size_t directoryOffset = optional + (info.is64Bit ? 112 : 96);
        const auto directoryCount = view.u32le(numberOffset);
        if (directoryCount) {
            const auto available = (*optionalSize > (info.is64Bit ? 112u : 96u))
                ? (*optionalSize - (info.is64Bit ? 112u : 96u)) / 8u : 0u;
            const auto count = std::min<std::uint32_t>({*directoryCount, 16u, static_cast<std::uint32_t>(available)});
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto address = view.u32le(directoryOffset + i * 8);
                const auto size = view.u32le(directoryOffset + i * 8 + 4);
                if (address && size) info.directories.push_back({i, *address, *size});
            }
            if (*directoryCount > available)
                diag(info, "PE_DIRECTORIES_TRUNCATED", "Declared data directories exceed optional-header bounds", numberOffset);
        }

        const std::uint64_t sectionTable = static_cast<std::uint64_t>(optional) + *optionalSize;
        const std::uint64_t sectionBytes = static_cast<std::uint64_t>(*sectionCount) * 40u;
        if (!rangeFits(sectionTable, sectionBytes, image.size())) {
            diag(info, "PE_SECTIONS_TRUNCATED", "Section table extends beyond file", static_cast<std::size_t>(std::min<std::uint64_t>(sectionTable, image.size())));
            return info;
        }
        for (std::uint16_t i = 0; i < *sectionCount; ++i) {
            const auto offset = static_cast<std::size_t>(sectionTable + static_cast<std::uint64_t>(i) * 40u);
            const auto virtualSize = view.u32le(offset + 8);
            const auto address = view.u32le(offset + 12);
            const auto rawSize = view.u32le(offset + 16);
            const auto rawOffset = view.u32le(offset + 20);
            const auto characteristics = view.u32le(offset + 36);
            if (!virtualSize || !address || !rawSize || !rawOffset || !characteristics) {
                diag(info, "PE_SECTION_TRUNCATED", "Section header fields are truncated", offset);
                break;
            }
            info.sections.push_back({name8(image, offset), *rawOffset, *rawSize, *address,
                                     *virtualSize, (*characteristics & 0x20000000u) != 0});
        }
        validateSections(info, image);

        // PE data-directory entries (except SECURITY/CERTIFICATE_TABLE) use
        // RVAs. Validate the complete range, not only its first byte.
        for (const auto& directory : info.directories) {
            if (directory.address == 0 && directory.size == 0) continue;
            if (directory.address == 0 || directory.size == 0) {
                diag(info, "PE_DIRECTORY_INCOMPLETE",
                     "Data directory has only one of address and size set",
                     numberOffset + static_cast<std::size_t>(directory.index) * 8);
                continue;
            }

            if (directory.index == 4) { // IMAGE_DIRECTORY_ENTRY_SECURITY is a file offset.
                if (!rangeFits(directory.address, directory.size, image.size())) {
                    diag(info, "PE_SECURITY_DIRECTORY_RANGE",
                         "Certificate table extends beyond the file",
                         static_cast<std::size_t>(std::min<std::uint64_t>(directory.address, image.size())));
                }
                continue;
            }

            bool mapped = directory.address < 0x1000 &&
                          rangeFits(directory.address, directory.size, image.size());
            for (const auto& section : info.sections) {
                if (directory.address < section.address) continue;
                const auto delta = directory.address - section.address;
                if (delta <= section.size && directory.size <= section.size - delta &&
                    rangeFits(section.offset + delta, directory.size, image.size())) {
                    mapped = true;
                    break;
                }
            }
            if (!mapped) {
                diag(info, "PE_DIRECTORY_UNMAPPED",
                     "Data directory RVA range is not fully backed by file data",
                     static_cast<std::size_t>(std::min<std::uint64_t>(directory.address, image.size())));
            }
        }

        if (info.entryPoint != 0) {
            bool entryMapped = info.entryPoint < 0x1000 &&
                               rangeFits(info.entryPoint, 1, image.size());
            for (const auto& section : info.sections) {
                if (info.entryPoint >= section.address &&
                    info.entryPoint - section.address < section.size) {
                    entryMapped = true;
                    break;
                }
            }
            if (!entryMapped)
                diag(info, "PE_ENTRYPOINT_UNMAPPED",
                     "Entry point RVA is not backed by file data",
                     static_cast<std::size_t>(std::min<std::uint64_t>(info.entryPoint, image.size())));
        }

        info.valid = info.diagnostics.valid;
        return info;
    }

    if (image.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' &&
        bytes[2] == 'L' && bytes[3] == 'F') {
        info.format = Format::ELF;
        if (!image.contains(0, 16)) {
            diag(info, "ELF_IDENT_TRUNCATED", "ELF identification is truncated", 0);
            return info;
        }
        if (bytes[4] != 1 && bytes[4] != 2) {
            diag(info, "ELF_CLASS_INVALID", "ELF class must be ELF32 or ELF64", 4);
            return info;
        }
        if (bytes[5] != 1) {
            diag(info, "ELF_ENDIAN_UNSUPPORTED", "Only little-endian ELF is supported", 5);
            return info;
        }
        if (bytes[6] != 1) {
            diag(info, "ELF_VERSION_INVALID", "Unsupported ELF identification version", 6);
            return info;
        }
        info.is64Bit = bytes[4] == 2;
        const std::size_t headerSize = info.is64Bit ? 64 : 52;
        if (!image.contains(0, headerSize)) {
            diag(info, "ELF_TRUNCATED", "ELF header is truncated", 0);
            return info;
        }
        info.entryPoint = info.is64Bit ? view.u64le(24).value_or(0) : view.u32le(24).value_or(0);
        const std::uint64_t phoff = info.is64Bit ? view.u64le(32).value_or(0) : view.u32le(28).value_or(0);
        const auto ehsize = view.u16le(info.is64Bit ? 52 : 40).value_or(0);
        const auto phentsize = view.u16le(info.is64Bit ? 54 : 42).value_or(0);
        const auto phnum = view.u16le(info.is64Bit ? 56 : 44).value_or(0);
        const std::uint16_t minimumProgramHeader = info.is64Bit ? 56 : 32;
        if (ehsize < headerSize) diag(info, "ELF_EHSIZE_INVALID", "ELF header size is smaller than its class minimum", info.is64Bit ? 52 : 40);
        if (phnum != 0 && phentsize < minimumProgramHeader) {
            diag(info, "ELF_PHENTSIZE_INVALID", "Program-header entry size is too small", info.is64Bit ? 54 : 42);
            return info;
        }
        if (phnum > 4096) {
            diag(info, "ELF_PHNUM_LIMIT", "Program-header count exceeds safety limit", info.is64Bit ? 56 : 44);
            return info;
        }
        if (phnum && (phentsize != 0) &&
            (phoff > std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(phnum) * phentsize ||
             !rangeFits(phoff, static_cast<std::uint64_t>(phnum) * phentsize, image.size()))) {
            diag(info, "ELF_PH_RANGE", "Program-header table extends beyond file", static_cast<std::size_t>(std::min<std::uint64_t>(phoff, image.size())));
            return info;
        }
        for (std::uint16_t i = 0; i < phnum; ++i) {
            const auto p = static_cast<std::size_t>(phoff + static_cast<std::uint64_t>(i) * phentsize);
            const auto type = view.u32le(p);
            if (!type) { diag(info, "ELF_PH_TRUNCATED", "Program header is truncated", p); break; }
            if (*type != 1) continue; // PT_LOAD
            std::uint64_t fileOffset = 0, address = 0, fileSize = 0, memorySize = 0, alignment = 0;
            std::uint32_t flags = 0;
            if (info.is64Bit) {
                flags = view.u32le(p + 4).value_or(0);
                fileOffset = view.u64le(p + 8).value_or(0);
                address = view.u64le(p + 16).value_or(0);
                fileSize = view.u64le(p + 32).value_or(0);
                memorySize = view.u64le(p + 40).value_or(0);
                alignment = view.u64le(p + 48).value_or(0);
            } else {
                fileOffset = view.u32le(p + 4).value_or(0);
                address = view.u32le(p + 8).value_or(0);
                fileSize = view.u32le(p + 16).value_or(0);
                memorySize = view.u32le(p + 20).value_or(0);
                flags = view.u32le(p + 24).value_or(0);
                alignment = view.u32le(p + 28).value_or(0);
            }

            if (fileSize > memorySize)
                diag(info, "ELF_LOAD_SIZE_INVALID", "PT_LOAD p_filesz exceeds p_memsz", p);
            if (!rangeFits(fileOffset, fileSize, image.size()))
                diag(info, "ELF_LOAD_FILE_RANGE", "PT_LOAD file range extends beyond file", p);
            if (memorySize > std::numeric_limits<std::uint64_t>::max() - address)
                diag(info, "ELF_LOAD_VIRTUAL_OVERFLOW", "PT_LOAD virtual address range overflows", p);
            if ((flags & ~7u) != 0)
                diag(info, "ELF_LOAD_FLAGS_INVALID", "PT_LOAD contains unsupported permission flag bits", p);
            if (alignment > 1) {
                if ((alignment & (alignment - 1)) != 0)
                    diag(info, "ELF_LOAD_ALIGN_INVALID", "PT_LOAD alignment is not a power of two", p);
                else if ((address % alignment) != (fileOffset % alignment))
                    diag(info, "ELF_LOAD_ALIGN_MISMATCH", "PT_LOAD virtual address and file offset are incongruent", p);
            }

            info.sections.push_back({"LOAD", fileOffset, fileSize, address, memorySize, (flags & 1u) != 0});
        }

        if (info.entryPoint != 0) {
            bool entryInExecutableLoad = false;
            for (const auto& segment : info.sections) {
                if (segment.executable && info.entryPoint >= segment.address &&
                    info.entryPoint - segment.address < segment.virtualSize) {
                    entryInExecutableLoad = true;
                    break;
                }
            }
            if (!entryInExecutableLoad)
                diag(info, "ELF_ENTRYPOINT_NOT_EXECUTABLE",
                     "ELF entry point is not inside an executable PT_LOAD segment",
                     0);
        }
        info.valid = info.diagnostics.valid;
        return info;
    }

    if (image.size() >= 4) {
        const auto magic = view.u32le(0).value_or(0);
        if (magic == 0xfeedfacf || magic == 0xfeedface) {
            info.format = Format::MachO;
            info.is64Bit = magic == 0xfeedfacf;
            const std::size_t headerSize = info.is64Bit ? 32 : 28;
            if (!image.contains(0, headerSize)) {
                diag(info, "MACHO_HEADER_TRUNCATED", "Mach-O header is truncated", 0);
                return info;
            }
            const auto commandCount = view.u32le(16).value_or(0);
            const auto commandBytes = view.u32le(20).value_or(0);
            if (commandCount > 65536 || !rangeFits(headerSize, commandBytes, image.size())) {
                diag(info, "MACHO_COMMAND_RANGE", "Mach-O load-command table is invalid or truncated", headerSize);
                return info;
            }
            std::uint64_t cursor = headerSize;
            const std::uint64_t commandEnd = cursor + commandBytes;
            for (std::uint32_t i = 0; i < commandCount; ++i) {
                if (!rangeFits(cursor, 8, static_cast<std::size_t>(commandEnd))) {
                    diag(info, "MACHO_COMMAND_TRUNCATED", "Mach-O load command header is truncated", static_cast<std::size_t>(cursor));
                    break;
                }
                const auto command = view.u32le(static_cast<std::size_t>(cursor)).value_or(0);
                const auto size = view.u32le(static_cast<std::size_t>(cursor) + 4).value_or(0);
                if (size < 8 || !rangeFits(cursor, size, static_cast<std::size_t>(commandEnd))) {
                    diag(info, "MACHO_COMMAND_SIZE", "Mach-O load command has an invalid cmdsize", static_cast<std::size_t>(cursor));
                    break;
                }
                const bool segment = (info.is64Bit && command == 0x19) || (!info.is64Bit && command == 1);
                const std::size_t minimumSegmentSize = info.is64Bit ? 72 : 56;
                if (segment) {
                    if (size < minimumSegmentSize) {
                        diag(info, "MACHO_SEGMENT_TRUNCATED", "Mach-O segment command is too small", static_cast<std::size_t>(cursor));
                        break;
                    }
                    const auto base = static_cast<std::size_t>(cursor);
                    const auto vmAddress = info.is64Bit ? view.u64le(base + 24).value_or(0) : view.u32le(base + 24).value_or(0);
                    const auto vmSize = info.is64Bit ? view.u64le(base + 32).value_or(0) : view.u32le(base + 28).value_or(0);
                    const auto fileOffset = info.is64Bit ? view.u64le(base + 40).value_or(0) : view.u32le(base + 32).value_or(0);
                    const auto fileSize = info.is64Bit ? view.u64le(base + 48).value_or(0) : view.u32le(base + 36).value_or(0);
                    const auto protection = view.u32le(base + (info.is64Bit ? 60 : 44)).value_or(0);
                    if (!rangeFits(fileOffset, fileSize, image.size()))
                        diag(info, "MACHO_SEGMENT_FILE_RANGE", "Mach-O segment file range extends beyond file", base);
                    if (fileSize > vmSize)
                        diag(info, "MACHO_SEGMENT_SIZE", "Mach-O segment filesize exceeds virtual size", base);
                    info.sections.push_back({name8(image, base + 8), fileOffset, fileSize, vmAddress, vmSize, (protection & 4u) != 0});
                }
                cursor += size;
            }
            if (cursor != commandEnd)
                diag(info, "MACHO_COMMAND_BYTES", "Mach-O command sizes do not match sizeofcmds", static_cast<std::size_t>(cursor));
            info.valid = info.diagnostics.valid;
            return info;
        }
    }

    diag(info, "FORMAT_UNKNOWN", "Unrecognized or unsupported binary format", 0);
    return info;
}

std::optional<std::uint64_t> rvaToOffset(const FormatInfo& info, std::uint64_t rva) {
    if (info.format != Format::PE) return std::nullopt;
    for (const auto& section : info.sections) {
        const auto span = std::max(section.size, section.virtualSize);
        if (rva < section.address || rva - section.address >= span) continue;
        const auto delta = rva - section.address;
        if (delta >= section.size || section.offset > std::numeric_limits<std::uint64_t>::max() - delta)
            return std::nullopt;
        return section.offset + delta;
    }
    return rva < 0x1000 ? std::optional<std::uint64_t>(rva) : std::nullopt;
}

std::optional<std::uint64_t> offsetToRva(const FormatInfo& info, std::uint64_t offset) {
    for (const auto& section : info.sections) {
        if (offset >= section.offset && offset - section.offset < section.size) {
            const auto delta = offset - section.offset;
            if (section.address > std::numeric_limits<std::uint64_t>::max() - delta) return std::nullopt;
            return section.address + delta;
        }
    }
    return offset < 0x1000 ? std::optional<std::uint64_t>(offset) : std::nullopt;
}

std::optional<std::uint64_t> vaToRva(const FormatInfo& info, std::uint64_t va) {
    if (va < info.imageBase) return std::nullopt;
    return va - info.imageBase;
}

std::vector<EmbeddedPayload> detectEmbeddedPayloads(const BinaryImage& image) {
    std::vector<EmbeddedPayload> payloads;
    const auto& bytes = image.bytes();
    for (std::size_t i = 0; i + 4 <= bytes.size(); ++i) {
        if (bytes[i] == 'M' && bytes[i + 1] == 'Z')
            payloads.push_back({"PE", i});
        else if (bytes[i] == 0x7f && bytes[i + 1] == 'E' && bytes[i + 2] == 'L' && bytes[i + 3] == 'F')
            payloads.push_back({"ELF", i});
        else if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 3 && bytes[i + 3] == 4)
            payloads.push_back({"ZIP", i});
        else if (bytes[i] == 0x1f && bytes[i + 1] == 0x8b)
            payloads.push_back({"GZIP", i});
    }
    return payloads;
}

} // namespace lulz::binary
