#include "binary/BinaryFormats.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

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
            info.architecture = view.u32le(4).value_or(0);
            info.architectureSubtype = view.u32le(8).value_or(0);
            info.fileType = view.u32le(12).value_or(0);
            const auto commandCount = view.u32le(16).value_or(0);
            const auto commandBytes = view.u32le(20).value_or(0);
            if (commandCount > 65536 || !rangeFits(headerSize, commandBytes, image.size())) {
                diag(info, "MACHO_COMMAND_RANGE", "Mach-O load-command table is invalid or truncated", headerSize);
                return info;
            }
            std::uint64_t cursor = headerSize;
            const std::uint64_t commandEnd = cursor + commandBytes;
            bool hasMainCommand = false;
            bool hasUnixThreadCommand = false;
            bool hasSymbolTableCommand = false;
            std::uint32_t symbolOffset = 0, symbolCount = 0, stringOffset = 0, stringSize = 0;
            std::uint32_t externalRelocationOffset = 0, externalRelocationCount = 0;
            std::uint32_t localRelocationOffset = 0, localRelocationCount = 0;
            std::uint32_t indirectSymbolOffset = 0, indirectSymbolCount = 0;
            std::uint32_t symbolTableOfContentsOffset = 0, symbolTableOfContentsCount = 0, moduleTableOffset = 0, moduleTableCount = 0;
            std::uint32_t externalReferenceSymbolOffset = 0, externalReferenceSymbolCount = 0;
            std::uint32_t localSymbolIndex = 0, localSymbolCount = 0;
            std::uint32_t externalSymbolIndex = 0, externalSymbolCount = 0;
            std::uint32_t undefinedSymbolIndex = 0, undefinedSymbolCount = 0;
            bool hasDynamicSymbolTable = false;
            bool hasTwoLevelHintsCommand = false;
            std::uint32_t twoLevelHintsOffset = 0, twoLevelHintsCount = 0;
            bool hasCodeSignatureCommand = false;
            bool hasDyldInfoCommand = false;
            std::array<std::uint32_t, 10> dyldStreamFields{};
            std::uint32_t codeSignatureOffset = 0, codeSignatureSize = 0;
            struct SectionRelocationTable { std::uint32_t offset; std::uint32_t count; std::uint64_t sectionSize; std::size_t diagnosticOffset; };
            std::vector<SectionRelocationTable> sectionRelocationTables;
            std::vector<Section> machoSegments;
            std::uint64_t unixThreadEntryPoint = 0;
            for (std::uint32_t i = 0; i < commandCount; ++i) {
                if (!rangeFits(cursor, 8, static_cast<std::size_t>(commandEnd))) {
                    diag(info, "MACHO_COMMAND_TRUNCATED", "Mach-O load command header is truncated", static_cast<std::size_t>(cursor));
                    break;
                }
                const auto command = view.u32le(static_cast<std::size_t>(cursor)).value_or(0);
                const auto size = view.u32le(static_cast<std::size_t>(cursor) + 4).value_or(0);
                const std::uint32_t commandAlignment = info.is64Bit ? 8u : 4u;
                if (size < 8 || (size % commandAlignment) != 0 ||
                    !rangeFits(cursor, size, static_cast<std::size_t>(commandEnd))) {
                    diag(info, "MACHO_COMMAND_SIZE", "Mach-O load command has an invalid or misaligned cmdsize", static_cast<std::size_t>(cursor));
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
                    const auto maxProtection = view.u32le(base + (info.is64Bit ? 56 : 40)).value_or(0);
                    const auto protection = view.u32le(base + (info.is64Bit ? 60 : 44)).value_or(0);
                    const auto sectionCount = view.u32le(base + (info.is64Bit ? 64 : 48)).value_or(0);
                    const std::uint64_t sectionEntrySize = info.is64Bit ? 80u : 68u;
                    const std::uint64_t sectionTableBytes = static_cast<std::uint64_t>(sectionCount) * sectionEntrySize;
                    if (sectionCount > (std::numeric_limits<std::uint64_t>::max() - minimumSegmentSize) / sectionEntrySize ||
                        minimumSegmentSize + sectionTableBytes > size) {
                        diag(info, "MACHO_SECTION_TABLE_SIZE", "Mach-O section table exceeds its load command", base);
                        break;
                    }
                    if (size < minimumSegmentSize + sectionTableBytes) {
                        diag(info, "MACHO_SECTION_TABLE_TRUNCATED", "Mach-O segment command does not contain all declared sections", base);
                        break;
                    }
                    if (!rangeFits(fileOffset, fileSize, image.size()))
                        diag(info, "MACHO_SEGMENT_FILE_RANGE", "Mach-O segment file range extends beyond file", base);
                    if (fileSize > vmSize)
                        diag(info, "MACHO_SEGMENT_SIZE", "Mach-O segment filesize exceeds virtual size", base);
                    if (vmSize > std::numeric_limits<std::uint64_t>::max() - vmAddress)
                        diag(info, "MACHO_SEGMENT_VIRTUAL_OVERFLOW", "Mach-O segment virtual address range overflows", base);
                    if ((protection & ~7u) != 0 || (maxProtection & ~7u) != 0 ||
                        (protection & ~maxProtection) != 0)
                        diag(info, "MACHO_SEGMENT_PROTECTION", "Mach-O segment protections are invalid or exceed maximum protections", base);
                    info.sections.push_back({name8(image, base + 8), fileOffset, fileSize, vmAddress, vmSize, (protection & 4u) != 0});
                    machoSegments.push_back({name8(image, base + 8), fileOffset, fileSize, vmAddress, vmSize, (protection & 4u) != 0});
                    for (std::uint32_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
                        const auto sectionBase = base + static_cast<std::size_t>(minimumSegmentSize +
                            static_cast<std::uint64_t>(sectionIndex) * sectionEntrySize);
                        const auto sectionAddress = info.is64Bit
                            ? view.u64le(sectionBase + 32).value_or(0)
                            : view.u32le(sectionBase + 32).value_or(0);
                        const auto sectionSize = info.is64Bit
                            ? view.u64le(sectionBase + 40).value_or(0)
                            : view.u32le(sectionBase + 36).value_or(0);
                        const auto sectionFileOffset = view.u32le(sectionBase + (info.is64Bit ? 48 : 40)).value_or(0);
                        const auto sectionFlags = view.u32le(sectionBase + (info.is64Bit ? 64 : 56)).value_or(0);
                        const auto sectionType = sectionFlags & 0xffu;
                        if (sectionType == 0x9u || sectionType == 0xau) { // S_MOD_INIT_FUNC_POINTERS / S_MOD_TERM_FUNC_POINTERS
                            const std::uint64_t pointerSize = info.is64Bit ? 8u : 4u;
                            if (!rangeFits(sectionFileOffset, sectionSize, image.size())) {
                                diag(info, "MACHO_INIT_TERM_SECTION_RANGE",
                                     "Mach-O init/term pointer section extends beyond the file", sectionBase);
                            } else if ((sectionSize % pointerSize) != 0) {
                                diag(info, "MACHO_INIT_TERM_SECTION_SIZE",
                                     "Mach-O init/term pointer section size is not pointer-aligned", sectionBase);
                            } else if (sectionSize > 0 && sectionAddress > std::numeric_limits<std::uint64_t>::max() - sectionSize) {
                                diag(info, "MACHO_INIT_TERM_ADDRESS_OVERFLOW",
                                     "Mach-O init/term pointer section virtual range overflows", sectionBase);
                            } else {
                                const bool initializer = sectionType == 0x9u;
                                for (std::uint64_t pointerOffset = 0; pointerOffset < sectionSize; pointerOffset += pointerSize) {
                                    const auto pointerFileOffset = static_cast<std::size_t>(
                                        static_cast<std::uint64_t>(sectionFileOffset) + pointerOffset);
                                    const auto target = info.is64Bit
                                        ? view.u64le(pointerFileOffset).value_or(0)
                                        : view.u32le(pointerFileOffset).value_or(0);
                                    if (target == 0) {
                                        diag(info, "MACHO_INIT_TERM_NULL_TARGET",
                                             "Mach-O init/term pointer entry is null", pointerFileOffset);
                                        continue;
                                    }
                                    const auto segmentEnd = vmAddress <= std::numeric_limits<std::uint64_t>::max() - vmSize
                                        ? vmAddress + vmSize : 0;
                                    if ((protection & 4u) == 0 || segmentEnd == 0 ||
                                        target < vmAddress || target >= segmentEnd) {
                                        diag(info, "MACHO_INIT_TERM_TARGET_NOT_EXECUTABLE",
                                             "Mach-O init/term pointer does not target its executable segment", pointerFileOffset);
                                        continue;
                                    }
                                    info.initTermPointers.push_back({sectionAddress + pointerOffset, target, initializer});
                                }
                            }
                        }
                        const auto relocationOffset = view.u32le(sectionBase + (info.is64Bit ? 56 : 48)).value_or(0);
                        const auto relocationCount = view.u32le(sectionBase + (info.is64Bit ? 60 : 52)).value_or(0);
                        if (relocationCount != 0)
                            sectionRelocationTables.push_back({relocationOffset, relocationCount, sectionSize, sectionBase});
                    }
                } else if (command == 0x5u) { // LC_UNIXTHREAD
                    const auto base = static_cast<std::size_t>(cursor);
                    if (hasUnixThreadCommand) {
                        diag(info, "MACHO_UNIXTHREAD_DUPLICATE", "Mach-O image contains more than one LC_UNIXTHREAD command", base);
                        break;
                    }
                    hasUnixThreadCommand = true;
                    if (info.architecture != 0x01000007u) {
                        // The thread-state layouts are architecture-specific. Preserve
                        // the command but do not interpret an unknown CPU layout.
                    } else {
                        std::uint64_t stateCursor = cursor + 8;
                        const std::uint64_t stateEnd = cursor + size;
                        bool foundX64State = false;
                        while (stateCursor < stateEnd) {
                            if (!rangeFits(stateCursor, 8, static_cast<std::size_t>(stateEnd))) {
                                diag(info, "MACHO_UNIXTHREAD_FLAVOR_TRUNCATED", "LC_UNIXTHREAD flavor/count header is truncated", static_cast<std::size_t>(stateCursor));
                                break;
                            }
                            const auto flavor = view.u32le(static_cast<std::size_t>(stateCursor)).value_or(0);
                            const auto count = view.u32le(static_cast<std::size_t>(stateCursor) + 4).value_or(0);
                            const std::uint64_t stateBytes = static_cast<std::uint64_t>(count) * 4u;
                            const std::uint64_t stateData = stateCursor + 8;
                            if (!rangeFits(stateData, stateBytes, static_cast<std::size_t>(stateEnd))) {
                                diag(info, "MACHO_UNIXTHREAD_STATE_RANGE", "LC_UNIXTHREAD register state exceeds command bounds", static_cast<std::size_t>(stateCursor));
                                break;
                            }
                            if (flavor == 4u) { // x86_THREAD_STATE64
                                if (foundX64State) {
                                    diag(info, "MACHO_UNIXTHREAD_STATE_DUPLICATE", "LC_UNIXTHREAD contains duplicate x86-64 thread states", static_cast<std::size_t>(stateCursor));
                                    break;
                                }
                                foundX64State = true;
                                if (count != 42u) {
                                    diag(info, "MACHO_UNIXTHREAD_STATE_SIZE", "x86_THREAD_STATE64 must contain exactly 42 32-bit words", static_cast<std::size_t>(stateCursor) + 4);
                                    break;
                                }
                                // x86_thread_state64_t.rip is the 17th 64-bit register.
                                unixThreadEntryPoint = view.u64le(static_cast<std::size_t>(stateData) + 16u * 8u).value_or(0);
                            }
                            stateCursor = stateData + stateBytes;
                        }
                        if (!foundX64State)
                            diag(info, "MACHO_UNIXTHREAD_STATE_MISSING", "LC_UNIXTHREAD has no x86_THREAD_STATE64 record", base);
                    }
                } else if (command == 0x2u) { // LC_SYMTAB
                    const auto base = static_cast<std::size_t>(cursor);
                    if (size < 24) {
                        diag(info, "MACHO_SYMTAB_TRUNCATED", "LC_SYMTAB command is smaller than its required fields", base);
                        break;
                    }
                    if (hasSymbolTableCommand) {
                        diag(info, "MACHO_SYMTAB_DUPLICATE", "Mach-O image contains more than one LC_SYMTAB command", base);
                        break;
                    }
                    hasSymbolTableCommand = true;
                    symbolOffset = view.u32le(base + 8).value_or(0);
                    symbolCount = view.u32le(base + 12).value_or(0);
                    stringOffset = view.u32le(base + 16).value_or(0);
                    stringSize = view.u32le(base + 20).value_or(0);
                } else if (command == 0xbu) { // LC_DYSYMTAB
                    const auto base = static_cast<std::size_t>(cursor);
                    if (size < 80) {
                        diag(info, "MACHO_DYSYMTAB_TRUNCATED", "LC_DYSYMTAB command is smaller than its required fields", base);
                        break;
                    }
                    if (hasDynamicSymbolTable) {
                        diag(info, "MACHO_DYSYMTAB_DUPLICATE", "Mach-O image contains more than one LC_DYSYMTAB command", base);
                        break;
                    }
                    hasDynamicSymbolTable = true;
                    localSymbolIndex = view.u32le(base + 8).value_or(0);
                    localSymbolCount = view.u32le(base + 12).value_or(0);
                    externalSymbolIndex = view.u32le(base + 16).value_or(0);
                    externalSymbolCount = view.u32le(base + 20).value_or(0);
                    undefinedSymbolIndex = view.u32le(base + 24).value_or(0);
                    undefinedSymbolCount = view.u32le(base + 28).value_or(0);
                    indirectSymbolOffset = view.u32le(base + 56).value_or(0);
                    indirectSymbolCount = view.u32le(base + 60).value_or(0);
                    symbolTableOfContentsOffset = view.u32le(base + 32).value_or(0);
                    symbolTableOfContentsCount = view.u32le(base + 36).value_or(0);
                    moduleTableOffset = view.u32le(base + 40).value_or(0);
                    moduleTableCount = view.u32le(base + 44).value_or(0);
                    externalReferenceSymbolOffset = view.u32le(base + 48).value_or(0);
                    externalReferenceSymbolCount = view.u32le(base + 52).value_or(0);
                    externalRelocationOffset = view.u32le(base + 64).value_or(0);
                    externalRelocationCount = view.u32le(base + 68).value_or(0);
                    localRelocationOffset = view.u32le(base + 72).value_or(0);
                    localRelocationCount = view.u32le(base + 76).value_or(0);
                } else if (command == 0x16u) { // LC_TWOLEVEL_HINTS
                    const auto base = static_cast<std::size_t>(cursor);
                    if (size < 16) {
                        diag(info, "MACHO_TWOLEVEL_HINTS_TRUNCATED",
                             "LC_TWOLEVEL_HINTS command is smaller than its required fields", base);
                        break;
                    }
                    if (hasTwoLevelHintsCommand) {
                        diag(info, "MACHO_TWOLEVEL_HINTS_DUPLICATE",
                             "Mach-O image contains more than one LC_TWOLEVEL_HINTS command", base);
                        break;
                    }
                    hasTwoLevelHintsCommand = true;
                    twoLevelHintsOffset = view.u32le(base + 8).value_or(0);
                    twoLevelHintsCount = view.u32le(base + 12).value_or(0);
                } else if (command == 0x22u || command == 0x80000022u) { // LC_DYLD_INFO / LC_DYLD_INFO_ONLY
                    const auto base = static_cast<std::size_t>(cursor);
                    if (size < 48) {
                        diag(info, "MACHO_DYLD_INFO_TRUNCATED",
                             "LC_DYLD_INFO command is smaller than its required fields", base);
                        break;
                    }
                    if (hasDyldInfoCommand) {
                        diag(info, "MACHO_DYLD_INFO_DUPLICATE",
                             "Mach-O image contains more than one LC_DYLD_INFO command", base);
                        break;
                    }
                    hasDyldInfoCommand = true;
                    for (std::size_t field = 0; field < dyldStreamFields.size(); ++field)
                        dyldStreamFields[field] = view.u32le(base + 8 + field * 4).value_or(0);
                } else if (command == 0x1du) { // LC_CODE_SIGNATURE
                    const auto base = static_cast<std::size_t>(cursor);
                    if (size < 16) {
                        diag(info, "MACHO_CODE_SIGNATURE_TRUNCATED",
                             "LC_CODE_SIGNATURE command is smaller than its required fields", base);
                        break;
                    }
                    if (hasCodeSignatureCommand) {
                        diag(info, "MACHO_CODE_SIGNATURE_DUPLICATE",
                             "Mach-O image contains more than one LC_CODE_SIGNATURE command", base);
                        break;
                    }
                    hasCodeSignatureCommand = true;
                    codeSignatureOffset = view.u32le(base + 8).value_or(0);
                    codeSignatureSize = view.u32le(base + 12).value_or(0);
                } else if (command == 0x80000028u) { // LC_MAIN
                    const auto base = static_cast<std::size_t>(cursor);
                    if (size < 24) {
                        diag(info, "MACHO_MAIN_TRUNCATED", "LC_MAIN command is smaller than its required fields", base);
                        break;
                    }
                    if (hasMainCommand) {
                        diag(info, "MACHO_MAIN_DUPLICATE", "Mach-O image contains more than one LC_MAIN command", base);
                        break;
                    }
                    hasMainCommand = true;
                    info.entryFileOffset = view.u64le(base + 8).value_or(0);
                    info.entryStackSize = view.u64le(base + 16).value_or(0);
                    if (!rangeFits(info.entryFileOffset, 1, image.size())) {
                        diag(info, "MACHO_MAIN_FILE_RANGE", "LC_MAIN entryoff is outside the file", base + 8);
                    }
                }
                cursor += size;
            }
            if (cursor != commandEnd)
                diag(info, "MACHO_COMMAND_BYTES", "Mach-O command sizes do not match sizeofcmds", static_cast<std::size_t>(cursor));

            if (hasDyldInfoCommand) {
                constexpr MachODyldStreamKind kinds[] = {
                    MachODyldStreamKind::Rebase, MachODyldStreamKind::Bind,
                    MachODyldStreamKind::WeakBind, MachODyldStreamKind::LazyBind,
                    MachODyldStreamKind::Export
                };
                constexpr const char* rangeCodes[] = {
                    "MACHO_DYLD_REBASE_RANGE", "MACHO_DYLD_BIND_RANGE",
                    "MACHO_DYLD_WEAK_BIND_RANGE", "MACHO_DYLD_LAZY_BIND_RANGE",
                    "MACHO_DYLD_EXPORT_RANGE"
                };
                constexpr const char* rangeMessages[] = {
                    "Mach-O dyld rebase stream extends beyond the file",
                    "Mach-O dyld bind stream extends beyond the file",
                    "Mach-O dyld weak-bind stream extends beyond the file",
                    "Mach-O dyld lazy-bind stream extends beyond the file",
                    "Mach-O dyld export stream extends beyond the file"
                };
                for (std::size_t stream = 0; stream < 5; ++stream) {
                    const auto offset = dyldStreamFields[stream * 2];
                    const auto length = dyldStreamFields[stream * 2 + 1];
                    if (length == 0) continue;
                    if (!rangeFits(offset, length, image.size())) {
                        diag(info, rangeCodes[stream], rangeMessages[stream], offset);
                        continue;
                    }
                    info.dyldStreams.push_back({kinds[stream], offset, length});
                }
                const auto rebaseOffset = dyldStreamFields[0];
                const auto rebaseSize = dyldStreamFields[1];
                if (rebaseSize != 0 && rangeFits(rebaseOffset, rebaseSize, image.size())) {
                    std::uint64_t streamCursor = rebaseOffset;
                    const std::uint64_t streamEnd = static_cast<std::uint64_t>(rebaseOffset) + rebaseSize;
                    std::uint8_t rebaseType = 0;
                    std::uint32_t segmentIndex = 0;
                    std::uint64_t segmentOffset = 0;
                    bool hasSegment = false;
                    bool terminated = false;
                    std::size_t emitted = 0;
                    constexpr std::size_t maxRebaseEntries = 1000000;

                    const auto readULEB = [&](std::uint64_t& cursor, std::uint64_t& value) -> bool {
                        value = 0;
                        unsigned shift = 0;
                        while (cursor < streamEnd) {
                            const auto byte = bytes[static_cast<std::size_t>(cursor++)];
                            const auto payload = static_cast<std::uint64_t>(byte & 0x7fu);
                            if (shift >= 64 || (shift == 63 && payload > 1u) ||
                                (shift < 63 && payload > (std::numeric_limits<std::uint64_t>::max() >> shift)))
                                return false;
                            value |= payload << shift;
                            if ((byte & 0x80u) == 0) return true;
                            if (shift > 56) return false;
                            shift += 7;
                        }
                        return false;
                    };
                    const auto addOffset = [&](std::uint64_t amount) -> bool {
                        if (amount > std::numeric_limits<std::uint64_t>::max() - segmentOffset) return false;
                        segmentOffset += amount;
                        return true;
                    };
                    const auto emitRebase = [&]() -> bool {
                        if (!hasSegment || rebaseType < 1 || rebaseType > 3 ||
                            segmentIndex >= machoSegments.size() || emitted >= maxRebaseEntries)
                            return false;
                        const auto& segmentInfo = machoSegments[segmentIndex];
                        const std::uint64_t pointerSize = info.is64Bit ? 8u : 4u;
                        const std::uint64_t width = rebaseType == 1 ? pointerSize : 4u;
                        if (segmentOffset > segmentInfo.virtualSize ||
                            width > segmentInfo.virtualSize - segmentOffset ||
                            segmentOffset > segmentInfo.size || width > segmentInfo.size - segmentOffset ||
                            segmentInfo.address > std::numeric_limits<std::uint64_t>::max() - segmentOffset ||
                            segmentInfo.offset > std::numeric_limits<std::uint64_t>::max() - segmentOffset)
                            return false;
                        const auto fileOffset = segmentInfo.offset + segmentOffset;
                        if (!rangeFits(fileOffset, width, image.size())) return false;
                        info.rebases.push_back({segmentIndex, rebaseType, segmentOffset,
                                                segmentInfo.address + segmentOffset, fileOffset});
                        ++emitted;
                        return addOffset(width);
                    };

                    while (streamCursor < streamEnd && !terminated) {
                        const auto opcodeByte = bytes[static_cast<std::size_t>(streamCursor++)];
                        const auto opcode = static_cast<std::uint8_t>(opcodeByte & 0xf0u);
                        const auto immediate = static_cast<std::uint8_t>(opcodeByte & 0x0fu);
                        std::uint64_t value = 0;
                        bool validOpcode = true;
                        switch (opcode) {
                        case 0x00u: // REBASE_OPCODE_DONE
                            terminated = true;
                            break;
                        case 0x10u: // REBASE_OPCODE_SET_TYPE_IMM
                            if (immediate < 1 || immediate > 3) validOpcode = false;
                            else rebaseType = immediate;
                            break;
                        case 0x20u: // REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                            segmentIndex = immediate;
                            hasSegment = segmentIndex < machoSegments.size();
                            if (!readULEB(streamCursor, value)) validOpcode = false;
                            else segmentOffset = value;
                            if (!hasSegment) validOpcode = false;
                            break;
                        case 0x30u: // REBASE_OPCODE_ADD_ADDR_ULEB
                            if (!readULEB(streamCursor, value) || !addOffset(value)) validOpcode = false;
                            break;
                        case 0x40u: // REBASE_OPCODE_ADD_ADDR_IMM_SCALED
                            if (!addOffset(static_cast<std::uint64_t>(immediate) * (info.is64Bit ? 8u : 4u)))
                                validOpcode = false;
                            break;
                        case 0x50u: // REBASE_OPCODE_DO_REBASE_IMM_TIMES
                            for (std::uint8_t i = 0; i < immediate && validOpcode; ++i)
                                validOpcode = emitRebase();
                            break;
                        case 0x60u: // REBASE_OPCODE_DO_REBASE_ULEB_TIMES
                            if (!readULEB(streamCursor, value) || value > maxRebaseEntries - emitted)
                                validOpcode = false;
                            else for (std::uint64_t i = 0; i < value && validOpcode; ++i)
                                validOpcode = emitRebase();
                            break;
                        case 0x70u: // REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
                            if (!emitRebase() || !readULEB(streamCursor, value) || !addOffset(value))
                                validOpcode = false;
                            break;
                        case 0x80u: { // REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                            std::uint64_t skip = 0;
                            if (!readULEB(streamCursor, value) || !readULEB(streamCursor, skip) ||
                                value > maxRebaseEntries - emitted) {
                                validOpcode = false;
                                break;
                            }
                            for (std::uint64_t i = 0; i < value && validOpcode; ++i)
                                validOpcode = emitRebase() && addOffset(skip);
                            break;
                        }
                        default:
                            validOpcode = false;
                            break;
                        }
                        if (!validOpcode) {
                            diag(info, "MACHO_REBASE_OPCODE",
                                 "Mach-O dyld rebase stream contains an invalid opcode, operand, segment, or rebase location",
                                 static_cast<std::size_t>(streamCursor - 1));
                            break;
                        }
                    }
                    if (!terminated && streamCursor == streamEnd)
                        diag(info, "MACHO_REBASE_UNTERMINATED",
                             "Mach-O dyld rebase stream does not end with REBASE_OPCODE_DONE",
                             static_cast<std::size_t>(rebaseOffset));
                }

                // Classic dyld bind stream. Weak and lazy bind streams are
                // deliberately handled by their own passes.
                const auto bindOffset = dyldStreamFields[2];
                const auto bindSize = dyldStreamFields[3];
                if (bindSize != 0 && rangeFits(bindOffset, bindSize, image.size())) {
                    std::uint64_t streamCursor = bindOffset;
                    const std::uint64_t streamEnd = static_cast<std::uint64_t>(bindOffset) + bindSize;
                    std::uint32_t segmentIndex = 0;
                    std::uint64_t segmentOffset = 0;
                    std::uint8_t bindType = 1;
                    std::uint8_t symbolFlags = 0;
                    std::int32_t libraryOrdinal = 0;
                    std::int64_t addend = 0;
                    std::string symbolName;
                    bool hasSegment = false;
                    bool hasSymbol = false;
                    bool terminated = false;
                    std::size_t emitted = 0;
                    constexpr std::size_t maxBindEntries = 1000000;

                    const auto readULEB = [&](std::uint64_t& value) -> bool {
                        value = 0;
                        unsigned shift = 0;
                        while (streamCursor < streamEnd) {
                            const auto byte = bytes[static_cast<std::size_t>(streamCursor++)];
                            const auto payload = static_cast<std::uint64_t>(byte & 0x7fu);
                            if (shift >= 64 || (shift == 63 && payload > 1u) ||
                                (shift < 63 && payload > (std::numeric_limits<std::uint64_t>::max() >> shift)))
                                return false;
                            value |= payload << shift;
                            if ((byte & 0x80u) == 0) return true;
                            if (shift > 56) return false;
                            shift += 7;
                        }
                        return false;
                    };
                    const auto readSLEB = [&](std::int64_t& value) -> bool {
                        std::uint64_t raw = 0;
                        unsigned shift = 0;
                        std::uint8_t byte = 0;
                        bool complete = false;
                        for (unsigned count = 0; count < 10 && streamCursor < streamEnd; ++count) {
                            byte = bytes[static_cast<std::size_t>(streamCursor++)];
                            const auto payload = static_cast<std::uint64_t>(byte & 0x7fu);
                            if (shift == 63 && payload != 0 && payload != 0x7fu) return false;
                            if (shift < 64) raw |= payload << shift;
                            shift += 7;
                            if ((byte & 0x80u) == 0) { complete = true; break; }
                        }
                        if (!complete) return false;
                        if (shift < 64 && (byte & 0x40u) != 0) raw |= (~std::uint64_t{0}) << shift;
                        value = static_cast<std::int64_t>(raw);
                        return true;
                    };
                    const auto addOffset = [&](std::uint64_t amount) -> bool {
                        if (amount > std::numeric_limits<std::uint64_t>::max() - segmentOffset) return false;
                        segmentOffset += amount;
                        return true;
                    };
                    const auto emitBind = [&]() -> bool {
                        if (!hasSegment || !hasSymbol || symbolName.empty() ||
                            bindType < 1 || bindType > 3 ||
                            segmentIndex >= machoSegments.size() || emitted >= maxBindEntries)
                            return false;
                        const auto& segmentInfo = machoSegments[segmentIndex];
                        const std::uint64_t pointerSize = info.is64Bit ? 8u : 4u;
                        const std::uint64_t width = bindType == 1 ? pointerSize : 4u;
                        if (segmentOffset > segmentInfo.virtualSize ||
                            width > segmentInfo.virtualSize - segmentOffset ||
                            segmentOffset > segmentInfo.size || width > segmentInfo.size - segmentOffset ||
                            segmentInfo.address > std::numeric_limits<std::uint64_t>::max() - segmentOffset ||
                            segmentInfo.offset > std::numeric_limits<std::uint64_t>::max() - segmentOffset)
                            return false;
                        const auto fileOffset = segmentInfo.offset + segmentOffset;
                        if (!rangeFits(fileOffset, width, image.size())) return false;
                        info.binds.push_back({segmentIndex, bindType, libraryOrdinal, symbolFlags,
                                              symbolName, addend, segmentOffset,
                                              segmentInfo.address + segmentOffset, fileOffset});
                        ++emitted;
                        return addOffset(width);
                    };

                    while (streamCursor < streamEnd && !terminated) {
                        const auto opcodeByte = bytes[static_cast<std::size_t>(streamCursor++)];
                        const auto opcode = static_cast<std::uint8_t>(opcodeByte & 0xf0u);
                        const auto immediate = static_cast<std::uint8_t>(opcodeByte & 0x0fu);
                        std::uint64_t value = 0;
                        bool validOpcode = true;
                        switch (opcode) {
                        case 0x00u: // BIND_OPCODE_DONE
                            terminated = true;
                            break;
                        case 0x10u: // BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
                            libraryOrdinal = immediate;
                            break;
                        case 0x20u: // BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
                            if (!readULEB(value) || value > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
                                validOpcode = false;
                            else libraryOrdinal = static_cast<std::int32_t>(value);
                            break;
                        case 0x30u: // BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
                            libraryOrdinal = immediate == 0 ? 0 : static_cast<std::int32_t>(immediate) - 16;
                            break;
                        case 0x40u: { // BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
                            symbolFlags = immediate;
                            const auto nameStart = streamCursor;
                            while (streamCursor < streamEnd &&
                                   bytes[static_cast<std::size_t>(streamCursor)] != 0)
                                ++streamCursor;
                            if (streamCursor == streamEnd) {
                                validOpcode = false;
                                break;
                            }
                            symbolName.assign(reinterpret_cast<const char*>(
                                bytes.data() + static_cast<std::size_t>(nameStart)),
                                static_cast<std::size_t>(streamCursor - nameStart));
                            ++streamCursor;
                            hasSymbol = !symbolName.empty();
                            if (!hasSymbol) validOpcode = false;
                            break;
                        }
                        case 0x50u: // BIND_OPCODE_SET_TYPE_IMM
                            if (immediate < 1 || immediate > 3) validOpcode = false;
                            else bindType = immediate;
                            break;
                        case 0x60u: // BIND_OPCODE_SET_ADDEND_SLEB
                            if (!readSLEB(addend)) validOpcode = false;
                            break;
                        case 0x70u: // BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                            segmentIndex = immediate;
                            hasSegment = segmentIndex < machoSegments.size();
                            if (!readULEB(value)) validOpcode = false;
                            else segmentOffset = value;
                            if (!hasSegment) validOpcode = false;
                            break;
                        case 0x80u: // BIND_OPCODE_ADD_ADDR_ULEB
                            if (!readULEB(value) || !addOffset(value)) validOpcode = false;
                            break;
                        case 0x90u: // BIND_OPCODE_DO_BIND
                            if (!emitBind()) validOpcode = false;
                            break;
                        case 0xa0u: // BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
                            if (!emitBind() || !readULEB(value) || !addOffset(value)) validOpcode = false;
                            break;
                        case 0xb0u: // BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
                            if (!emitBind() ||
                                !addOffset(static_cast<std::uint64_t>(immediate) * (info.is64Bit ? 8u : 4u)))
                                validOpcode = false;
                            break;
                        case 0xc0u: { // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                            std::uint64_t count = 0, skip = 0;
                            if (!readULEB(count) || !readULEB(skip) ||
                                count > maxBindEntries - emitted) {
                                validOpcode = false;
                                break;
                            }
                            for (std::uint64_t i = 0; i < count && validOpcode; ++i)
                                validOpcode = emitBind() && addOffset(skip);
                            break;
                        }
                        case 0xd0u: // BIND_OPCODE_THREADED
                            // Threaded bind tables require a separate pointer-chain
                            // interpreter; rejecting them is safer than misreporting.
                            validOpcode = false;
                            break;
                        default:
                            validOpcode = false;
                            break;
                        }
                        if (!validOpcode) {
                            diag(info, "MACHO_BIND_OPCODE",
                                 "Mach-O dyld bind stream contains an invalid opcode, operand, symbol, segment, or bind location",
                                 static_cast<std::size_t>(streamCursor - 1));
                            break;
                        }
                    }
                    if (!terminated && streamCursor == streamEnd)
                        diag(info, "MACHO_BIND_UNTERMINATED",
                             "Mach-O dyld bind stream does not end with BIND_OPCODE_DONE",
                             static_cast<std::size_t>(bindOffset));
                }
            }


                // Export trie: bounded graph traversal with cycle and malformed-node checks.
                const auto exportOffset = dyldStreamFields[8];
                const auto exportSize = dyldStreamFields[9];
                if (exportSize != 0 && rangeFits(exportOffset, exportSize, image.size())) {
                    constexpr std::size_t maxExportNodes = 100000;
                    const std::uint64_t exportEnd = static_cast<std::uint64_t>(exportOffset) + exportSize;
                    std::vector<std::uint8_t> visited(exportSize, 0);
                    std::vector<std::pair<std::uint64_t, std::string>> pending;
                    pending.push_back({0, {}});
                    std::size_t visitedCount = 0;
                    const auto readExportULEB = [&](std::uint64_t& pos, std::uint64_t limit,
                                                     std::uint64_t& value) -> bool {
                        value = 0;
                        unsigned shift = 0;
                        while (pos < limit) {
                            const auto byte = bytes[static_cast<std::size_t>(exportOffset + pos++)];
                            const auto payload = static_cast<std::uint64_t>(byte & 0x7fu);
                            if (shift >= 64 || (shift == 63 && payload > 1u) ||
                                (shift < 63 && payload > (std::numeric_limits<std::uint64_t>::max() >> shift)))
                                return false;
                            value |= payload << shift;
                            if ((byte & 0x80u) == 0) return true;
                            if (shift > 56) return false;
                            shift += 7;
                        }
                        return false;
                    };
                    while (!pending.empty()) {
                        auto current = std::move(pending.back());
                        pending.pop_back();
                        const auto nodeOffset = current.first;
                        if (nodeOffset >= exportSize) {
                            diag(info, "MACHO_EXPORT_NODE_OFFSET", "Mach-O export trie child points outside the trie", exportOffset);
                            break;
                        }
                        if (visited[static_cast<std::size_t>(nodeOffset)] != 0) {
                            diag(info, "MACHO_EXPORT_CYCLE", "Mach-O export trie contains a cycle or duplicate node reference", exportOffset + static_cast<std::size_t>(nodeOffset));
                            continue;
                        }
                        visited[static_cast<std::size_t>(nodeOffset)] = 1;
                        if (++visitedCount > maxExportNodes) {
                            diag(info, "MACHO_EXPORT_NODE_LIMIT", "Mach-O export trie exceeds the node processing limit", exportOffset);
                            break;
                        }
                        std::uint64_t pos = nodeOffset;
                        std::uint64_t terminalSize = 0;
                        if (!readExportULEB(pos, exportSize, terminalSize) ||
                            terminalSize > exportSize - pos) {
                            diag(info, "MACHO_EXPORT_TERMINAL_RANGE", "Mach-O export trie terminal payload is truncated or out of range", exportOffset + static_cast<std::size_t>(nodeOffset));
                            break;
                        }
                        const auto terminalEnd = pos + terminalSize;
                        if (terminalSize != 0) {
                            std::uint64_t flags = 0, address = 0, other = 0;
                            std::string importedName;
                            bool validTerminal = readExportULEB(pos, terminalEnd, flags);
                            constexpr std::uint64_t EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08u;
                            constexpr std::uint64_t EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10u;
                            if (validTerminal && (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0) {
                                validTerminal = readExportULEB(pos, terminalEnd, other);
                                if (validTerminal) {
                                    while (pos < terminalEnd && bytes[static_cast<std::size_t>(exportOffset + pos)] != 0)
                                        importedName.push_back(static_cast<char>(bytes[static_cast<std::size_t>(exportOffset + pos++)]));
                                    if (pos >= terminalEnd) validTerminal = false;
                                    else ++pos;
                                }
                            } else if (validTerminal) {
                                validTerminal = readExportULEB(pos, terminalEnd, address);
                                if (validTerminal && (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
                                    validTerminal = readExportULEB(pos, terminalEnd, other);
                            }
                            if (!validTerminal || pos != terminalEnd) {
                                diag(info, "MACHO_EXPORT_TERMINAL", "Mach-O export trie terminal payload has invalid flags or operands", exportOffset + static_cast<std::size_t>(nodeOffset));
                                break;
                            }
                            info.exports.push_back({current.second, flags, address, other,
                                (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0 ? other : 0,
                                std::move(importedName)});
                        }
                        pos = terminalEnd;
                        if (pos >= exportSize) {
                            diag(info, "MACHO_EXPORT_CHILD_COUNT", "Mach-O export trie node is missing its child count", exportOffset + static_cast<std::size_t>(nodeOffset));
                            break;
                        }
                        const auto childCount = bytes[static_cast<std::size_t>(exportOffset + pos++)];
                        for (std::uint32_t child = 0; child < childCount; ++child) {
                            std::string edge;
                            while (pos < exportSize && bytes[static_cast<std::size_t>(exportOffset + pos)] != 0)
                                edge.push_back(static_cast<char>(bytes[static_cast<std::size_t>(exportOffset + pos++)]));
                            if (pos >= exportSize || edge.empty()) {
                                diag(info, "MACHO_EXPORT_EDGE", "Mach-O export trie child edge is empty or unterminated", exportOffset + static_cast<std::size_t>(nodeOffset));
                                break;
                            }
                            ++pos;
                            std::uint64_t childOffset = 0;
                            if (!readExportULEB(pos, exportSize, childOffset)) {
                                diag(info, "MACHO_EXPORT_CHILD_OFFSET", "Mach-O export trie child offset is malformed", exportOffset + static_cast<std::size_t>(nodeOffset));
                                break;
                            }
                            pending.push_back({childOffset, current.second + edge});
                        }
                        if (!info.diagnostics.valid) break;
                    }
                }

            if (hasDynamicSymbolTable) {
                const auto validateSymbolRange = [&](std::uint32_t index, std::uint32_t count, const char* code, const char* description) {
                    const std::uint64_t end = static_cast<std::uint64_t>(index) + count;
                    if (end > symbolCount) {
                        diag(info, code, description, 0);
                        return false;
                    }
                    return true;
                };
                validateSymbolRange(localSymbolIndex, localSymbolCount, "MACHO_DYSYMTAB_LOCAL_SYMBOL_RANGE",
                                    "LC_DYSYMTAB local symbol range exceeds LC_SYMTAB symbol count");
                validateSymbolRange(externalSymbolIndex, externalSymbolCount, "MACHO_DYSYMTAB_EXTERNAL_SYMBOL_RANGE",
                                    "LC_DYSYMTAB external symbol range exceeds LC_SYMTAB symbol count");
                validateSymbolRange(undefinedSymbolIndex, undefinedSymbolCount, "MACHO_DYSYMTAB_UNDEFINED_SYMBOL_RANGE",
                                    "LC_DYSYMTAB undefined symbol range exceeds LC_SYMTAB symbol count");
            }

            if (hasSymbolTableCommand) {
                const std::uint64_t symbolEntrySize = info.is64Bit ? 16u : 12u;
                const std::uint64_t symbolBytes = static_cast<std::uint64_t>(symbolCount) * symbolEntrySize;
                const bool symbolRangeValid = rangeFits(symbolOffset, symbolBytes, image.size());
                const bool stringRangeValid = rangeFits(stringOffset, stringSize, image.size());
                if (!symbolRangeValid)
                    diag(info, "MACHO_SYMTAB_RANGE", "Mach-O symbol table extends beyond the file", symbolOffset);
                if (!stringRangeValid)
                    diag(info, "MACHO_STRTAB_RANGE", "Mach-O string table extends beyond the file", stringOffset);

                if (symbolRangeValid && stringRangeValid) {
                    for (std::uint32_t i = 0; i < symbolCount; ++i) {
                        const auto entry = static_cast<std::size_t>(
                            static_cast<std::uint64_t>(symbolOffset) + static_cast<std::uint64_t>(i) * symbolEntrySize);
                        const auto stringIndex = view.u32le(entry).value_or(0);
                        const auto symbolType = view.u8(entry + 4).value_or(0);
                        const auto sectionIndex = view.u8(entry + 5).value_or(0);
                        const auto description = view.u16le(entry + 6).value_or(0);
                        const std::uint64_t value = info.is64Bit
                            ? view.u64le(entry + 8).value_or(0)
                            : view.u32le(entry + 8).value_or(0);

                        std::string symbolName;
                        if (stringIndex != 0) {
                            if (stringIndex >= stringSize) {
                                diag(info, "MACHO_SYMBOL_STRING_INDEX", "Mach-O symbol string index is outside the string table", entry);
                                continue;
                            }
                            const auto nameStart = static_cast<std::uint64_t>(stringOffset) + stringIndex;
                            const auto nameLimit = static_cast<std::uint64_t>(stringOffset) + stringSize;
                            bool terminated = false;
                            for (auto pos = nameStart; pos < nameLimit; ++pos) {
                                const auto ch = bytes[static_cast<std::size_t>(pos)];
                                if (ch == 0) {
                                    terminated = true;
                                    break;
                                }
                                symbolName.push_back(static_cast<char>(ch));
                            }
                            if (!terminated) {
                                diag(info, "MACHO_SYMBOL_NAME_UNTERMINATED", "Mach-O symbol name is not NUL-terminated within the string table", entry);
                                continue;
                            }
                        }
                        info.symbols.push_back({std::move(symbolName), symbolType, sectionIndex, description, value});
                    }
                }
            }

            if (hasTwoLevelHintsCommand) {
                constexpr std::uint64_t hintEntrySize = 4;
                const auto hintBytes = static_cast<std::uint64_t>(twoLevelHintsCount) * hintEntrySize;
                if (!rangeFits(twoLevelHintsOffset, hintBytes, image.size())) {
                    diag(info, "MACHO_TWOLEVEL_HINTS_RANGE",
                         "Mach-O two-level hints table extends beyond the file", twoLevelHintsOffset);
                } else {
                    info.twoLevelHints.reserve(twoLevelHintsCount);
                    for (std::uint32_t i = 0; i < twoLevelHintsCount; ++i) {
                        const auto entry = static_cast<std::size_t>(
                            static_cast<std::uint64_t>(twoLevelHintsOffset) +
                            static_cast<std::uint64_t>(i) * hintEntrySize);
                        const auto raw = view.u32le(entry).value_or(0);
                        const auto subImage = static_cast<std::uint8_t>(raw >> 24);
                        const auto tocIndex = raw & 0x00ffffffu;
                        if (subImage == 0 && tocIndex >= symbolTableOfContentsCount) {
                            diag(info, "MACHO_TWOLEVEL_HINTS_TOC_INDEX",
                                 "Mach-O two-level hint references a missing local TOC entry", entry);
                            continue;
                        }
                        info.twoLevelHints.push_back({subImage, tocIndex});
                    }
                }
            }

            if (hasCodeSignatureCommand) {
                info.codeSignatureOffset = codeSignatureOffset;
                info.codeSignatureSize = codeSignatureSize;
                if (codeSignatureOffset == 0 || codeSignatureSize < 12 ||
                    !rangeFits(codeSignatureOffset, codeSignatureSize, image.size())) {
                    diag(info, "MACHO_CODE_SIGNATURE_RANGE",
                         "Mach-O code signature range is empty, too small, or outside the file",
                         codeSignatureOffset);
                } else {
                    constexpr std::uint32_t CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0u;
                    const auto signatureMagic = view.u32be(codeSignatureOffset).value_or(0);
                    const auto signatureLength = view.u32be(static_cast<std::size_t>(codeSignatureOffset) + 4).value_or(0);
                    const auto blobCount = view.u32be(static_cast<std::size_t>(codeSignatureOffset) + 8).value_or(0);
                    info.codeSignatureMagic = signatureMagic;
                    if (signatureMagic != CSMAGIC_EMBEDDED_SIGNATURE) {
                        diag(info, "MACHO_CODE_SIGNATURE_MAGIC",
                             "Mach-O LC_CODE_SIGNATURE does not reference an embedded SuperBlob",
                             codeSignatureOffset);
                    } else if (signatureLength < 12 || signatureLength > codeSignatureSize ||
                               static_cast<std::uint64_t>(blobCount) >
                                   (static_cast<std::uint64_t>(signatureLength) - 12u) / 8u) {
                        diag(info, "MACHO_CODE_SIGNATURE_SUPERBLOB",
                             "Mach-O code-signature SuperBlob length or index count is invalid",
                             codeSignatureOffset);
                    } else {
                        const std::uint64_t indexEnd = 12u + static_cast<std::uint64_t>(blobCount) * 8u;
                        info.codeSignatureBlobs.reserve(blobCount);
                        for (std::uint32_t i = 0; i < blobCount; ++i) {
                            const auto indexEntry = static_cast<std::size_t>(
                                static_cast<std::uint64_t>(codeSignatureOffset) + 12u +
                                static_cast<std::uint64_t>(i) * 8u);
                            const auto slotType = view.u32be(indexEntry).value_or(0);
                            const auto relativeOffset = view.u32be(indexEntry + 4).value_or(0);
                            if (relativeOffset < indexEnd ||
                                static_cast<std::uint64_t>(relativeOffset) + 8u > signatureLength) {
                                diag(info, "MACHO_CODE_SIGNATURE_BLOB_OFFSET",
                                     "Mach-O code-signature blob offset is outside the SuperBlob payload",
                                     indexEntry + 4);
                                continue;
                            }
                            const auto blobOffset = static_cast<std::uint64_t>(codeSignatureOffset) + relativeOffset;
                            const auto blobMagic = view.u32be(static_cast<std::size_t>(blobOffset)).value_or(0);
                            const auto blobLength = view.u32be(static_cast<std::size_t>(blobOffset) + 4).value_or(0);
                            if (blobLength < 8 || static_cast<std::uint64_t>(relativeOffset) + blobLength > signatureLength) {
                                diag(info, "MACHO_CODE_SIGNATURE_BLOB_RANGE",
                                     "Mach-O code-signature blob extends beyond the SuperBlob",
                                     static_cast<std::size_t>(blobOffset));
                                continue;
                            }
                            info.codeSignatureBlobs.push_back({slotType, blobMagic, blobLength, relativeOffset});
                        }
                    }
                }
            }

            if (hasDynamicSymbolTable) {
                constexpr std::uint64_t indirectSymbolEntrySize = 4;
                const auto indirectSymbolBytes = static_cast<std::uint64_t>(indirectSymbolCount) * indirectSymbolEntrySize;
                if (!rangeFits(indirectSymbolOffset, indirectSymbolBytes, image.size())) {
                    diag(info, "MACHO_INDIRECT_SYMTAB_RANGE",
                         "Mach-O indirect symbol table extends beyond the file", indirectSymbolOffset);
                } else {
                    info.indirectSymbols.reserve(indirectSymbolCount);
                    for (std::uint32_t i = 0; i < indirectSymbolCount; ++i) {
                        const auto entry = static_cast<std::size_t>(
                            static_cast<std::uint64_t>(indirectSymbolOffset) +
                            static_cast<std::uint64_t>(i) * indirectSymbolEntrySize);
                        const auto symbolIndex = view.u32le(entry).value_or(0);
                        constexpr std::uint32_t INDIRECT_SYMBOL_LOCAL = 0x80000000u;
                        constexpr std::uint32_t INDIRECT_SYMBOL_ABS = 0x40000000u;
                        if ((symbolIndex & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) == 0 &&
                            symbolIndex >= info.symbols.size()) {
                            diag(info, "MACHO_INDIRECT_SYMBOL_INDEX",
                                 "Mach-O indirect symbol entry references a missing symbol", entry);
                            continue;
                        }
                        info.indirectSymbols.push_back(symbolIndex);
                    }
                }
            }

            if (hasDynamicSymbolTable) {
                constexpr std::uint64_t externalReferenceEntrySize = 4;
                const auto externalReferenceBytes = static_cast<std::uint64_t>(externalReferenceSymbolCount) * externalReferenceEntrySize;
                if (!rangeFits(externalReferenceSymbolOffset, externalReferenceBytes, image.size())) {
                    diag(info, "MACHO_EXTREFS_RANGE",
                         "Mach-O external reference table extends beyond the file", externalReferenceSymbolOffset);
                } else {
                    info.externalReferences.reserve(externalReferenceSymbolCount);
                    for (std::uint32_t i = 0; i < externalReferenceSymbolCount; ++i) {
                        const auto entry = static_cast<std::size_t>(
                            static_cast<std::uint64_t>(externalReferenceSymbolOffset) +
                            static_cast<std::uint64_t>(i) * externalReferenceEntrySize);
                        const auto rawReference = view.u32le(entry).value_or(0);
                        const auto symbolIndex = rawReference >> 8;
                        const auto flags = static_cast<std::uint8_t>(rawReference & 0xffu);
                        if (symbolIndex >= info.symbols.size()) {
                            diag(info, "MACHO_EXTREFS_SYMBOL_INDEX",
                                 "Mach-O external reference entry references a missing symbol", entry);
                            continue;
                        }
                        info.externalReferences.push_back({symbolIndex, flags});
                    }
                }
            }

            if (hasDynamicSymbolTable) {
                const std::uint64_t moduleEntrySize = info.is64Bit ? 56u : 52u;
                const auto moduleTableBytes = static_cast<std::uint64_t>(moduleTableCount) * moduleEntrySize;
                if (!rangeFits(moduleTableOffset, moduleTableBytes, image.size())) {
                    diag(info, "MACHO_DYSYMTAB_MODULE_RANGE",
                         "Mach-O dynamic symbol table module table extends beyond the file", moduleTableOffset);
                } else {
                    info.modules.reserve(moduleTableCount);
                    for (std::uint32_t i = 0; i < moduleTableCount; ++i) {
                        const auto entry = static_cast<std::size_t>(static_cast<std::uint64_t>(moduleTableOffset) + static_cast<std::uint64_t>(i) * moduleEntrySize);
                        const auto nameIndex = view.u32le(entry).value_or(0);
                        MachOModule module;
                        module.externalSymbolIndex = view.u32le(entry + 4).value_or(0);
                        module.externalSymbolCount = view.u32le(entry + 8).value_or(0);
                        module.referenceSymbolIndex = view.u32le(entry + 12).value_or(0);
                        module.referenceSymbolCount = view.u32le(entry + 16).value_or(0);
                        module.localSymbolIndex = view.u32le(entry + 20).value_or(0);
                        module.localSymbolCount = view.u32le(entry + 24).value_or(0);
                        module.externalRelocationIndex = view.u32le(entry + 28).value_or(0);
                        module.externalRelocationCount = view.u32le(entry + 32).value_or(0);
                        module.initTermIndex = view.u32le(entry + 36).value_or(0);
                        module.initTermCount = view.u32le(entry + 40).value_or(0);
                        module.objcModuleInfoSize = view.u32le(entry + 44).value_or(0);
                        module.objcModuleInfoAddress = info.is64Bit ? view.u64le(entry + 48).value_or(0) : view.u32le(entry + 48).value_or(0);
                        const auto validateRange = [&](std::uint32_t index, std::uint32_t count, std::uint32_t limit,
                                                        const char* diagnosticCode, const char* message, std::size_t fieldOffset) {
                            if (static_cast<std::uint64_t>(index) + count > limit) {
                                diag(info, diagnosticCode, message, fieldOffset);
                                return false;
                            }
                            return true;
                        };
                        bool valid = true;
                        valid &= validateRange(module.externalSymbolIndex, module.externalSymbolCount, symbolCount,
                            "MACHO_MODULE_EXT_SYMBOL_RANGE", "Mach-O module external symbol range exceeds LC_SYMTAB", entry + 4);
                        valid &= validateRange(module.referenceSymbolIndex, module.referenceSymbolCount, externalReferenceSymbolCount,
                            "MACHO_MODULE_REFERENCE_RANGE", "Mach-O module reference range exceeds the external reference table", entry + 12);
                        valid &= validateRange(module.localSymbolIndex, module.localSymbolCount, symbolCount,
                            "MACHO_MODULE_LOCAL_SYMBOL_RANGE", "Mach-O module local symbol range exceeds LC_SYMTAB", entry + 20);
                        valid &= validateRange(module.externalRelocationIndex, module.externalRelocationCount, externalRelocationCount,
                            "MACHO_MODULE_EXT_RELOC_RANGE", "Mach-O module external relocation range exceeds LC_DYSYMTAB", entry + 28);
                        if (nameIndex >= stringSize) {
                            diag(info, "MACHO_MODULE_NAME_INDEX", "Mach-O module name index exceeds the string table", entry);
                            valid = false;
                        } else if (rangeFits(stringOffset, stringSize, image.size())) {
                            const auto nameStart = static_cast<std::uint64_t>(stringOffset) + nameIndex;
                            const auto nameEnd = static_cast<std::uint64_t>(stringOffset) + stringSize;
                            bool terminated = false;
                            for (auto pos = nameStart; pos < nameEnd; ++pos) {
                                const auto ch = bytes[static_cast<std::size_t>(pos)];
                                if (ch == 0) { terminated = true; break; }
                                module.name.push_back(static_cast<char>(ch));
                            }
                            if (!terminated) {
                                diag(info, "MACHO_MODULE_NAME_UNTERMINATED", "Mach-O module name is not NUL-terminated", entry);
                                valid = false;
                            }
                        } else {
                            diag(info, "MACHO_MODULE_STRING_TABLE_RANGE", "Mach-O module name cannot be read because the string table is invalid", entry);
                            valid = false;
                        }
                        if (valid) info.modules.push_back(std::move(module));
                    }
                }
            }

            if (hasDynamicSymbolTable) {
                constexpr std::uint64_t tocEntrySize = 8;
                const auto tocBytes = static_cast<std::uint64_t>(symbolTableOfContentsCount) * tocEntrySize;
                if (!rangeFits(symbolTableOfContentsOffset, tocBytes, image.size())) {
                    diag(info, "MACHO_DYSYMTAB_TOC_RANGE",
                         "Mach-O dynamic symbol table TOC extends beyond the file", symbolTableOfContentsOffset);
                } else {
                    info.symbolTableOfContents.reserve(symbolTableOfContentsCount);
                    for (std::uint32_t i = 0; i < symbolTableOfContentsCount; ++i) {
                        const auto entry = static_cast<std::size_t>(
                            static_cast<std::uint64_t>(symbolTableOfContentsOffset) +
                            static_cast<std::uint64_t>(i) * tocEntrySize);
                        const auto moduleIndex = view.u32le(entry).value_or(0);
                        const auto symbolIndex = view.u32le(entry + 4).value_or(0);
                        if (moduleIndex >= moduleTableCount) {
                            diag(info, "MACHO_DYSYMTAB_TOC_MODULE_INDEX",
                                 "Mach-O TOC entry references a missing module-table entry", entry);
                            continue;
                        }
                        if (symbolIndex >= info.symbols.size()) {
                            diag(info, "MACHO_DYSYMTAB_TOC_SYMBOL_INDEX",
                                 "Mach-O TOC entry references a missing symbol", entry + 4);
                            continue;
                        }
                        info.symbolTableOfContents.push_back({moduleIndex, symbolIndex});
                    }
                }
            }

            if (hasDynamicSymbolTable) {
                const auto parseRelocationTable = [&](std::uint32_t tableOffset, std::uint32_t count, bool externalTable) {
                    constexpr std::uint64_t relocationEntrySize = 8;
                    const std::uint64_t tableBytes = static_cast<std::uint64_t>(count) * relocationEntrySize;
                    if (!rangeFits(tableOffset, tableBytes, image.size())) {
                        diag(info, externalTable ? "MACHO_EXTRELOC_RANGE" : "MACHO_LOCRELOC_RANGE",
                             "Mach-O relocation table extends beyond the file", tableOffset);
                        return;
                    }
                    for (std::uint32_t i = 0; i < count; ++i) {
                        const auto entry = static_cast<std::size_t>(
                            static_cast<std::uint64_t>(tableOffset) + static_cast<std::uint64_t>(i) * relocationEntrySize);
                        const auto rawAddress = view.u32le(entry).value_or(0);
                        const auto word = view.u32le(entry + 4).value_or(0);
                        Relocation relocation;
                        relocation.address = static_cast<std::int32_t>(rawAddress);
                        if ((rawAddress & 0x80000000u) != 0) {
                            relocation.scattered = true;
                            relocation.address = static_cast<std::int32_t>(rawAddress & 0x00ffffffu);
                            relocation.type = static_cast<std::uint8_t>((rawAddress >> 24) & 0x0fu);
                            relocation.length = static_cast<std::uint8_t>((rawAddress >> 28) & 0x03u);
                            relocation.pcRelative = ((rawAddress >> 30) & 1u) != 0;
                            relocation.value = word;
                        } else {
                            relocation.symbolNumber = word & 0x00ffffffu;
                            relocation.pcRelative = ((word >> 24) & 1u) != 0;
                            relocation.length = static_cast<std::uint8_t>((word >> 25) & 0x03u);
                            relocation.external = ((word >> 27) & 1u) != 0;
                            relocation.type = static_cast<std::uint8_t>((word >> 28) & 0x0fu);
                            if (relocation.external && relocation.symbolNumber >= info.symbols.size()) {
                                diag(info, "MACHO_RELOCATION_SYMBOL_INDEX",
                                     "Mach-O external relocation references a missing symbol", entry + 4);
                                continue;
                            }
                            if (externalTable && !relocation.external) {
                                diag(info, "MACHO_EXTRELOC_NOT_EXTERNAL",
                                     "External relocation table contains a non-external relocation", entry + 4);
                                continue;
                            }
                        }
                        info.relocations.push_back(relocation);
                    }
                };
                parseRelocationTable(externalRelocationOffset, externalRelocationCount, true);
                parseRelocationTable(localRelocationOffset, localRelocationCount, false);
            }

            // Section relocation records are separate from LC_DYSYMTAB's
            // external/local relocation arrays. Parse them after LC_SYMTAB so
            // external symbol indices can be checked against the full symbol list.
            for (const auto& table : sectionRelocationTables) {
                constexpr std::uint64_t relocationEntrySize = 8;
                const auto tableBytes = static_cast<std::uint64_t>(table.count) * relocationEntrySize;
                if (!rangeFits(table.offset, tableBytes, image.size())) {
                    diag(info, "MACHO_SECTION_RELOC_RANGE",
                         "Mach-O section relocation table extends beyond the file", table.diagnosticOffset);
                    continue;
                }
                for (std::uint32_t relocationIndex = 0; relocationIndex < table.count; ++relocationIndex) {
                    const auto entry = static_cast<std::size_t>(
                        static_cast<std::uint64_t>(table.offset) +
                        static_cast<std::uint64_t>(relocationIndex) * relocationEntrySize);
                    const auto rawAddress = view.u32le(entry).value_or(0);
                    const auto word = view.u32le(entry + 4).value_or(0);
                    Relocation relocation;
                    relocation.address = static_cast<std::int32_t>(rawAddress);
                    if ((rawAddress & 0x80000000u) != 0) {
                        relocation.scattered = true;
                        relocation.address = static_cast<std::int32_t>(rawAddress & 0x00ffffffu);
                        relocation.type = static_cast<std::uint8_t>((rawAddress >> 24) & 0x0fu);
                        relocation.length = static_cast<std::uint8_t>((rawAddress >> 28) & 0x03u);
                        relocation.pcRelative = ((rawAddress >> 30) & 1u) != 0;
                        relocation.value = word;
                    } else {
                        relocation.symbolNumber = word & 0x00ffffffu;
                        relocation.pcRelative = ((word >> 24) & 1u) != 0;
                        relocation.length = static_cast<std::uint8_t>((word >> 25) & 0x03u);
                        relocation.external = ((word >> 27) & 1u) != 0;
                        relocation.type = static_cast<std::uint8_t>((word >> 28) & 0x0fu);
                        if (relocation.address < 0 ||
                            static_cast<std::uint64_t>(relocation.address) >= table.sectionSize) {
                            diag(info, "MACHO_SECTION_RELOC_ADDRESS",
                                 "Mach-O section relocation address is outside its section", entry);
                            continue;
                        }
                        if (relocation.external && relocation.symbolNumber >= info.symbols.size()) {
                            diag(info, "MACHO_SECTION_RELOC_SYMBOL_INDEX",
                                 "Mach-O section external relocation references a missing symbol", entry + 4);
                            continue;
                        }
                    }
                    info.relocations.push_back(relocation);
                }
            }

            if (hasMainCommand && hasUnixThreadCommand)
                diag(info, "MACHO_ENTRYPOINT_CONFLICT", "Mach-O image contains both LC_MAIN and LC_UNIXTHREAD entry-point commands", 0);

            if (!hasMainCommand && hasUnixThreadCommand && info.architecture == 0x01000007u) {
                info.entryPoint = unixThreadEntryPoint;
                bool mappedExecutableEntry = false;
                for (const auto& segment : info.sections) {
                    if (!segment.executable || unixThreadEntryPoint < segment.address ||
                        unixThreadEntryPoint - segment.address >= segment.virtualSize) continue;
                    info.entryPoint = unixThreadEntryPoint;
                    mappedExecutableEntry = true;
                    break;
                }
                if (unixThreadEntryPoint == 0 || !mappedExecutableEntry)
                    diag(info, "MACHO_UNIXTHREAD_ENTRY_NOT_EXECUTABLE",
                         "x86-64 thread RIP is not inside an executable segment", 0);
            }

            if (hasMainCommand && rangeFits(info.entryFileOffset, 1, image.size())) {
                bool mappedExecutableEntry = false;
                for (const auto& segment : info.sections) {
                    if (!segment.executable || info.entryFileOffset < segment.offset ||
                        info.entryFileOffset - segment.offset >= segment.size) continue;
                    const auto delta = info.entryFileOffset - segment.offset;
                    if (segment.address > std::numeric_limits<std::uint64_t>::max() - delta) continue;
                    const auto address = segment.address + delta;
                    if (segment.virtualSize == 0 || address < segment.address ||
                        address - segment.address >= segment.virtualSize) continue;
                    info.entryPoint = address;
                    mappedExecutableEntry = true;
                    break;
                }
                if (!mappedExecutableEntry)
                    diag(info, "MACHO_MAIN_NOT_EXECUTABLE",
                         "LC_MAIN entryoff is not backed by an executable segment",
                         static_cast<std::size_t>(std::min<std::uint64_t>(info.entryFileOffset, image.size())));
            }
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
