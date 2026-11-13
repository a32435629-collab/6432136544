
#include "lulz/formats/pe/PEParser.hpp"
#include "lulz/binary/BinaryReader.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lulz {
namespace {

bool addFits(std::size_t a, std::size_t b) {
    return b <= std::numeric_limits<std::size_t>::max() - a;
}

bool multiplyFits(std::size_t a, std::size_t b) {
    return a == 0 ||
        b <= std::numeric_limits<std::size_t>::max() / a;
}

Result<std::size_t> rvaToFileOffset(
    std::uint32_t rva,
    std::size_t length,
    const PEInfo& info,
    std::size_t fileSize
) {
    const std::uint64_t target = rva;

    for (const auto& section : info.sections) {
        const std::uint64_t start = section.virtualAddress;

        if (target < start) {
            continue;
        }

        const std::uint64_t delta = target - start;

        const std::uint64_t span = std::max(
            section.virtualSize,
            section.rawSize
        );

        if (delta >= span) {
            continue;
        }

        if (delta > section.rawSize ||
            length > std::uint64_t(section.rawSize) - delta) {
            return Result<std::size_t>::failure(
                "RVA points outside section raw data"
            );
        }

        const std::uint64_t offset =
            std::uint64_t(section.rawOffset) + delta;

        if (offset > fileSize ||
            length > std::uint64_t(fileSize) - offset) {
            return Result<std::size_t>::failure(
                "RVA maps outside file bounds"
            );
        }

        return Result<std::size_t>::success(
            static_cast<std::size_t>(offset)
        );
    }

    return Result<std::size_t>::failure(
        "RVA is not backed by a section"
    );
}

std::optional<std::string> readCString(
    std::span<const std::uint8_t> bytes,
    std::uint32_t rva,
    const PEInfo& info
) {
    std::string result;
    result.reserve(64);

    for (std::size_t i = 0; i < 4096; ++i) {
        const std::uint64_t current =
            std::uint64_t(rva) + i;

        if (current > 0xffffffffu) {
            return std::nullopt;
        }

        auto offset = rvaToFileOffset(
            static_cast<std::uint32_t>(current),
            1,
            info,
            bytes.size()
        );

        if (!offset) {
            return std::nullopt;
        }

        const std::uint8_t ch = bytes[offset.value()];

        if (ch == 0) {
            return result;
        }

        result.push_back(static_cast<char>(ch));
    }

    return std::nullopt;
}

bool isZeroImportDescriptor(
    std::span<const std::uint8_t> bytes,
    std::size_t offset
) {
    if (offset > bytes.size() ||
        20 > bytes.size() - offset) {
        return false;
    }

    for (std::size_t i = 0; i < 20; ++i) {
        if (bytes[offset + i] != 0) {
            return false;
        }
    }

    return true;
}

} // namespace

// -----------------------------------------------------------------------------
// PE Parser
// -----------------------------------------------------------------------------

Result<PEInfo> parsePE(
    std::span<const std::uint8_t> bytes
) {
    BinaryReader reader(bytes);

    auto mz = reader.u16le(0);

    if (!mz || mz.value() != 0x5a4d) {
        return Result<PEInfo>::failure(
            "missing MZ signature"
        );
    }

    auto peOffset = reader.u32le(0x3c);

    if (!peOffset) {
        return Result<PEInfo>::failure(
            "truncated DOS header"
        );
    }

    const std::size_t pe = peOffset.value();

    if (!addFits(pe, 24) ||
        pe + 24 > bytes.size()) {
        return Result<PEInfo>::failure(
            "PE header exceeds file bounds"
        );
    }

    auto signature = reader.u32le(pe);

    if (!signature || signature.value() != 0x00004550) {
        return Result<PEInfo>::failure(
            "missing PE signature"
        );
    }

    auto machine = reader.u16le(pe + 4);
    auto sectionCount = reader.u16le(pe + 6);
    auto timestamp = reader.u32le(pe + 8);
    auto optionalSize = reader.u16le(pe + 20);

    if (!machine || !sectionCount ||
        !timestamp || !optionalSize) {
        return Result<PEInfo>::failure(
            "truncated COFF header"
        );
    }

    const std::size_t optional = pe + 24;
    const std::size_t optionalLength = optionalSize.value();

    if (!addFits(optional, optionalLength) ||
        optional + optionalLength > bytes.size()) {
        return Result<PEInfo>::failure(
            "optional header exceeds file bounds"
        );
    }

    if (optionalLength < 2) {
        return Result<PEInfo>::failure(
            "optional header is too small"
        );
    }

    auto magic = reader.u16le(optional);

    if (!magic) {
        return Result<PEInfo>::failure(
            "truncated optional header"
        );
    }

    PEInfo info;

    info.machine = machine.value();
    info.sectionCount = sectionCount.value();
    info.timestamp = timestamp.value();

    std::size_t numberOfDirsOffset = 0;
    std::size_t directoryOffset = 0;

    if (magic.value() == 0x20b) {
        // PE32+

        if (optionalLength < 32) {
            return Result<PEInfo>::failure(
                "PE32+ optional header is too small"
            );
        }

        info.is64 = true;

        numberOfDirsOffset = 108;
        directoryOffset = 112;

        auto entryPoint = reader.u32le(optional + 16);
        auto imageBase = reader.u64le(optional + 24);

        if (!entryPoint || !imageBase) {
            return Result<PEInfo>::failure(
                "truncated PE32+ optional header"
            );
        }

        info.entryPoint = entryPoint.value();
        info.imageBase = imageBase.value();

    } else if (magic.value() == 0x10b) {
        // PE32

        if (optionalLength < 32) {
            return Result<PEInfo>::failure(
                "PE32 optional header is too small"
            );
        }

        numberOfDirsOffset = 92;
        directoryOffset = 96;

        auto entryPoint = reader.u32le(optional + 16);
        auto imageBase = reader.u32le(optional + 28);

        if (!entryPoint || !imageBase) {
            return Result<PEInfo>::failure(
                "truncated PE32 optional header"
            );
        }

        info.entryPoint = entryPoint.value();
        info.imageBase = imageBase.value();
        info.imageBase32 = imageBase.value();

    } else {
        return Result<PEInfo>::failure(
            "unsupported optional-header magic"
        );
    }

    // Data directories.

    if (optionalLength >= numberOfDirsOffset + 4) {
        auto directoryCount = reader.u32le(
            optional + numberOfDirsOffset
        );

        if (directoryCount) {
            auto readDirectory = [&](std::uint32_t index,
                                     std::uint32_t& rva,
                                     std::uint32_t& size) {
                const std::uint64_t entryEnd =
                    std::uint64_t(directoryOffset) +
                    (std::uint64_t(index) + 1) * 8;

                if (directoryCount.value() <= index ||
                    entryEnd > optionalLength) {
                    return;
                }

                const std::size_t offset =
                    optional +
                    directoryOffset +
                    std::size_t(index) * 8;

                auto directoryRva = reader.u32le(offset);
                auto directorySize = reader.u32le(offset + 4);

                if (directoryRva && directorySize) {
                    rva = directoryRva.value();
                    size = directorySize.value();
                }
            };

            // IMAGE_DIRECTORY_ENTRY_IMPORT
            readDirectory(
                1,
                info.importDirectoryRva,
                info.importDirectorySize
            );

            // IMAGE_DIRECTORY_ENTRY_EXCEPTION
            readDirectory(
                3,
                info.exceptionDirectoryRva,
                info.exceptionDirectorySize
            );
        }
    }

    // Section table.

    const std::size_t table = optional + optionalLength;

    if (info.sectionCount > 4096) {
        return Result<PEInfo>::failure(
            "unreasonable section count"
        );
    }

    if (!multiplyFits(info.sectionCount, 40)) {
        return Result<PEInfo>::failure(
            "section table size overflow"
        );
    }

    const std::size_t sectionBytes =
        std::size_t(info.sectionCount) * 40;

    if (!addFits(table, sectionBytes) ||
        table + sectionBytes > bytes.size()) {
        return Result<PEInfo>::failure(
            "truncated section table"
        );
    }

    info.sections.reserve(info.sectionCount);

    for (std::size_t i = 0; i < info.sectionCount; ++i) {
        const std::size_t offset = table + i * 40;

        auto sectionData = reader.slice(offset, 40);

        if (!sectionData) {
            return Result<PEInfo>::failure(
                "truncated section table"
            );
        }

        PESection section;

        for (std::size_t j = 0;
             j < 8 && sectionData.value()[j] != 0;
             ++j) {
            section.name.push_back(
                static_cast<char>(sectionData.value()[j])
            );
        }

        BinaryReader sectionReader(sectionData.value());

        auto virtualSize = sectionReader.u32le(8);
        auto virtualAddress = sectionReader.u32le(12);
        auto rawSize = sectionReader.u32le(16);
        auto rawOffset = sectionReader.u32le(20);
        auto characteristics = sectionReader.u32le(36);

        if (!virtualSize || !virtualAddress ||
            !rawSize || !rawOffset || !characteristics) {
            return Result<PEInfo>::failure(
                "invalid section record"
            );
        }

        section.virtualSize = virtualSize.value();
        section.virtualAddress = virtualAddress.value();
        section.rawSize = rawSize.value();
        section.rawOffset = rawOffset.value();
        section.characteristics = characteristics.value();

        info.sections.push_back(std::move(section));
    }

    return Result<PEInfo>::success(
        std::move(info)
    );
}

// -----------------------------------------------------------------------------
// PE Exception Directory (.pdata)
// -----------------------------------------------------------------------------

Result<std::vector<RuntimeFunctionEntry>>
parsePEExceptionDirectory(
    std::span<const std::uint8_t> bytes,
    const PEInfo& info
) {
    if (!info.is64) {
        return Result<std::vector<RuntimeFunctionEntry>>::failure(
            "PE exception directory parser currently supports x64 PE32+ only"
        );
    }

    if (info.exceptionDirectoryRva == 0 ||
        info.exceptionDirectorySize == 0) {
        return Result<std::vector<RuntimeFunctionEntry>>::failure(
            "PE exception directory is absent"
        );
    }

    if (info.exceptionDirectorySize % 12 != 0) {
        return Result<std::vector<RuntimeFunctionEntry>>::failure(
            "exception directory size is not a multiple of 12"
        );
    }

    auto offset = rvaToFileOffset(
        info.exceptionDirectoryRva,
        info.exceptionDirectorySize,
        info,
        bytes.size()
    );

    if (!offset) {
        return Result<std::vector<RuntimeFunctionEntry>>::failure(
            offset.error()
        );
    }

    BinaryReader reader(bytes);

    const std::size_t count =
        info.exceptionDirectorySize / 12;

    if (count > 1'000'000) {
        return Result<std::vector<RuntimeFunctionEntry>>::failure(
            "unreasonable runtime-function count"
        );
    }

    std::vector<RuntimeFunctionEntry> entries;
    entries.reserve(count);

    std::uint32_t previousBegin = 0;

    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t entryOffset =
            offset.value() + i * 12;

        auto begin = reader.u32le(entryOffset);
        auto end = reader.u32le(entryOffset + 4);
        auto unwind = reader.u32le(entryOffset + 8);

        if (!begin || !end || !unwind) {
            return Result<std::vector<RuntimeFunctionEntry>>::failure(
                "truncated RUNTIME_FUNCTION entry"
            );
        }

        if (begin.value() >= end.value()) {
            return Result<std::vector<RuntimeFunctionEntry>>::failure(
                "invalid RUNTIME_FUNCTION range"
            );
        }

        if (i != 0 && begin.value() < previousBegin) {
            return Result<std::vector<RuntimeFunctionEntry>>::failure(
                "RUNTIME_FUNCTION entries are not sorted"
            );
        }

        if (unwind.value() == 0) {
            return Result<std::vector<RuntimeFunctionEntry>>::failure(
                "RUNTIME_FUNCTION has null UNWIND_INFO RVA"
            );
        }

        // Проверяем начало диапазона.
        auto beginOffset = rvaToFileOffset(
            begin.value(),
            1,
            info,
            bytes.size()
        );

        // End RVA является исключительной границей.
        // Поэтому проверяем последний байт диапазона: endRva - 1.
        auto lastByteOffset = rvaToFileOffset(
            end.value() - 1,
            1,
            info,
            bytes.size()
        );

        // Проверяем заголовок UNWIND_INFO.
        auto unwindOffset = rvaToFileOffset(
            unwind.value(),
            4,
            info,
            bytes.size()
        );

        if (!beginOffset || !lastByteOffset) {
            return Result<std::vector<RuntimeFunctionEntry>>::failure(
                "RUNTIME_FUNCTION range is outside PE image"
            );
        }

        if (!unwindOffset) {
            return Result<std::vector<RuntimeFunctionEntry>>::failure(
                "UNWIND_INFO RVA is outside PE image"
            );
        }

        previousBegin = begin.value();

        entries.push_back({
            begin.value(),
            end.value(),
            unwind.value(),
            entryOffset
        });
    }

    return Result<std::vector<RuntimeFunctionEntry>>::success(
        std::move(entries)
    );
}

// -----------------------------------------------------------------------------
// PE Import Directory
// -----------------------------------------------------------------------------

Result<std::vector<ImportSymbol>> parsePEImports(
    std::span<const std::uint8_t> bytes,
    const PEInfo& info
) {
    if (info.importDirectoryRva == 0 ||
        info.importDirectorySize == 0) {
        return Result<std::vector<ImportSymbol>>::success({});
    }

    if (info.importDirectorySize < 20) {
        return Result<std::vector<ImportSymbol>>::failure(
            "import directory is too small"
        );
    }

    auto directoryOffset = rvaToFileOffset(
        info.importDirectoryRva,
        info.importDirectorySize,
        info,
        bytes.size()
    );

    if (!directoryOffset) {
        return Result<std::vector<ImportSymbol>>::failure(
            "import directory: " + directoryOffset.error()
        );
    }

    BinaryReader reader(bytes);

    const std::size_t descriptorCount =
        info.importDirectorySize / 20;

    if (descriptorCount > 65536) {
        return Result<std::vector<ImportSymbol>>::failure(
            "unreasonable import descriptor count"
        );
    }

    const std::size_t pointerSize =
        info.is64 ? 8 : 4;

    const std::uint64_t ordinalFlag = info.is64
        ? 0x8000000000000000ull
        : 0x80000000ull;

    std::vector<ImportSymbol> imports;

    bool foundTerminator = false;

    for (std::size_t d = 0; d < descriptorCount; ++d) {
        const std::size_t descriptorOffset =
            directoryOffset.value() + d * 20;

        if (isZeroImportDescriptor(bytes, descriptorOffset)) {
            foundTerminator = true;
            break;
        }

        auto originalThunk = reader.u32le(descriptorOffset);
        auto nameRva = reader.u32le(descriptorOffset + 12);
        auto firstThunk = reader.u32le(descriptorOffset + 16);

        if (!originalThunk || !nameRva || !firstThunk) {
            return Result<std::vector<ImportSymbol>>::failure(
                "invalid import descriptor"
            );
        }

        if (nameRva.value() == 0 ||
            firstThunk.value() == 0) {
            return Result<std::vector<ImportSymbol>>::failure(
                "invalid import descriptor fields"
            );
        }

        auto moduleOffset = rvaToFileOffset(
            nameRva.value(),
            1,
            info,
            bytes.size()
        );

        if (!moduleOffset) {
            return Result<std::vector<ImportSymbol>>::failure(
                "import module name RVA is outside PE image"
            );
        }

        auto module = readCString(
            bytes,
            nameRva.value(),
            info
        );

        if (!module) {
            return Result<std::vector<ImportSymbol>>::failure(
                "invalid or unterminated import module name"
            );
        }

        const std::uint32_t thunkRva =
            originalThunk.value() != 0
                ? originalThunk.value()
                : firstThunk.value();

        bool thunkTerminated = false;

        for (std::size_t t = 0; t < 65536; ++t) {
            const std::uint64_t thunkAddress =
                std::uint64_t(thunkRva) +
                std::uint64_t(t) * pointerSize;

            const std::uint64_t iatAddress =
                std::uint64_t(firstThunk.value()) +
                std::uint64_t(t) * pointerSize;

            if (thunkAddress > 0xffffffffu ||
                iatAddress > 0xffffffffu) {
                return Result<std::vector<ImportSymbol>>::failure(
                    "import thunk RVA overflow"
                );
            }

            auto thunkOffset = rvaToFileOffset(
                static_cast<std::uint32_t>(thunkAddress),
                pointerSize,
                info,
                bytes.size()
            );

            if (!thunkOffset) {
                return Result<std::vector<ImportSymbol>>::failure(
                    "import thunk: " + thunkOffset.error()
                );
            }

            std::uint64_t value = 0;

            if (info.is64) {
                auto entry = reader.u64le(thunkOffset.value());

                if (!entry) {
                    return Result<std::vector<ImportSymbol>>::failure(
                        "truncated 64-bit import thunk"
                    );
                }

                value = entry.value();

            } else {
                auto entry = reader.u32le(thunkOffset.value());

                if (!entry) {
                    return Result<std::vector<ImportSymbol>>::failure(
                        "truncated 32-bit import thunk"
                    );
                }

                value = entry.value();
            }

            if (value == 0) {
                thunkTerminated = true;
                break;
            }

            ImportSymbol symbol;

            symbol.module = *module;
            symbol.iatRva = static_cast<std::uint32_t>(iatAddress);

            if ((value & ordinalFlag) != 0) {
                symbol.byOrdinal = true;

                symbol.ordinal = static_cast<std::uint16_t>(
                    value & 0xffff
                );

                symbol.name =
                    "#" + std::to_string(symbol.ordinal);

            } else {
                if (value > 0xffffffffu) {
                    return Result<std::vector<ImportSymbol>>::failure(
                        "invalid import-by-name RVA"
                    );
                }

                const auto nameAddress =
                    static_cast<std::uint32_t>(value);

                auto hintOffset = rvaToFileOffset(
                    nameAddress,
                    2,
                    info,
                    bytes.size()
                );

                if (!hintOffset) {
                    return Result<std::vector<ImportSymbol>>::failure(
                        "invalid import hint/name entry"
                    );
                }

                const std::uint64_t actualNameRva =
                    std::uint64_t(nameAddress) + 2;

                if (actualNameRva > 0xffffffffu) {
                    return Result<std::vector<ImportSymbol>>::failure(
                        "import name RVA overflow"
                    );
                }

                auto name = readCString(
                    bytes,
                    static_cast<std::uint32_t>(actualNameRva),
                    info
                );

                if (!name) {
                    return Result<std::vector<ImportSymbol>>::failure(
                        "invalid or unterminated import symbol name"
                    );
                }

                symbol.name = *name;
            }

            imports.push_back(std::move(symbol));
        }

        if (!thunkTerminated) {
            return Result<std::vector<ImportSymbol>>::failure(
                "import thunk table has no terminator"
            );
        }
    }

    if (!foundTerminator) {
        return Result<std::vector<ImportSymbol>>::failure(
            "import descriptor table has no null terminator"
        );
    }

    return Result<std::vector<ImportSymbol>>::success(
        std::move(imports)
    );
}

} // namespace lulz
