#include "lulz/formats/pe/PEExtendedParser.hpp"
#include "lulz/binary/BinaryReader.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <string>
#include <utility>

namespace lulz {
namespace {

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
        if (delta > section.rawSize || length > std::uint64_t(section.rawSize) - delta) continue;
        const std::uint64_t offset = std::uint64_t(section.rawOffset) + delta;
        if (offset > bytes.size() || length > bytes.size() - static_cast<std::size_t>(offset)) return std::nullopt;
        return static_cast<std::size_t>(offset);
    }
    return std::nullopt;
}

std::optional<std::string> readString(
    std::span<const std::uint8_t> bytes,
    const PEInfo& pe,
    std::uint32_t rva,
    std::size_t limit = 4096
) {
    std::string result;
    for (std::size_t i = 0; i < limit; ++i) {
        const std::uint64_t current = std::uint64_t(rva) + i;
        if (current > 0xffffffffu) return std::nullopt;
        const auto offset = mapRva(bytes, pe, static_cast<std::uint32_t>(current), 1);
        if (!offset) return std::nullopt;
        const auto ch = bytes[*offset];
        if (ch == 0) return result;
        result.push_back(static_cast<char>(ch));
    }
    return std::nullopt;
}

bool readU16(const BinaryReader& reader, std::size_t offset, std::uint16_t& value) {
    const auto result = reader.u16le(offset);
    if (!result) return false;
    value = result.value();
    return true;
}
bool readU32(const BinaryReader& reader, std::size_t offset, std::uint32_t& value) {
    const auto result = reader.u32le(offset);
    if (!result) return false;
    value = result.value();
    return true;
}
bool readU64(const BinaryReader& reader, std::size_t offset, std::uint64_t& value) {
    const auto result = reader.u64le(offset);
    if (!result) return false;
    value = result.value();
    return true;
}


std::optional<std::uint32_t> delayFieldToRva(
    std::uint32_t value,
    bool rvaBased,
    const PEInfo& image
) {
    if (value == 0) return std::uint32_t{0};
    if (rvaBased) return value;
    if (std::uint64_t(value) < image.imageBase) return std::nullopt;
    const std::uint64_t rva = std::uint64_t(value) - image.imageBase;
    if (rva > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return static_cast<std::uint32_t>(rva);
}

void parseDelayImports(std::span<const std::uint8_t> bytes, PEExtendedInfo& out) {
    constexpr std::size_t descriptorSize = 32;
    constexpr std::size_t maxDescriptors = 65536;
    constexpr std::size_t maxThunks = 65536;
    const auto& directory = out.directories[13]; // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
    if (!directory.present()) return;
    if (directory.size < descriptorSize) {
        out.warnings.push_back("delay import directory is smaller than one descriptor");
        return;
    }
    if (directory.size % descriptorSize != 0)
        out.warnings.push_back("delay import directory size is not a multiple of 32");

    const auto directoryOffset = mapRva(bytes, out.image, directory.rva, directory.size);
    if (!directoryOffset) {
        out.warnings.push_back("delay import directory is outside section data");
        return;
    }

    const std::size_t descriptorCount = directory.size / descriptorSize;
    if (descriptorCount > maxDescriptors) {
        out.warnings.push_back("delay import descriptor count exceeds safety limit");
        return;
    }

    BinaryReader reader(bytes);
    const std::size_t pointerSize = out.image.is64 ? 8 : 4;
    const std::uint64_t ordinalFlag = out.image.is64
        ? 0x8000000000000000ull
        : 0x80000000ull;
    bool foundTerminator = false;

    for (std::size_t d = 0; d < descriptorCount; ++d) {
        const std::size_t descriptorOffset = *directoryOffset + d * descriptorSize;
        std::uint32_t fields[8]{};
        bool fieldsValid = true;
        bool allZero = true;
        for (std::size_t field = 0; field < 8; ++field) {
            if (!readU32(reader, descriptorOffset + field * 4, fields[field])) {
                fieldsValid = false;
                break;
            }
            allZero = allZero && fields[field] == 0;
        }
        if (!fieldsValid) {
            out.warnings.push_back("truncated delay import descriptor");
            return;
        }
        if (allZero) {
            foundTerminator = true;
            break;
        }

        const std::uint32_t attributes = fields[0];
        if ((attributes & ~1u) != 0) {
            out.warnings.push_back("delay import descriptor uses unsupported attribute flags");
            return;
        }
        const bool rvaBased = (attributes & 1u) != 0;
        const auto nameRva = delayFieldToRva(fields[1], rvaBased, out.image);
        const auto iatRva = delayFieldToRva(fields[3], rvaBased, out.image);
        auto intRva = delayFieldToRva(fields[4], rvaBased, out.image);
        if (!nameRva || !iatRva || !intRva || *nameRva == 0 || *iatRva == 0) {
            out.warnings.push_back("delay import descriptor contains an invalid name/IAT/INT address");
            return;
        }
        if (*intRva == 0) intRva = iatRva;

        const auto module = readString(bytes, out.image, *nameRva);
        if (!module) {
            out.warnings.push_back("delay import module name is invalid or unterminated");
            return;
        }

        bool thunkTerminated = false;
        for (std::size_t t = 0; t < maxThunks; ++t) {
            const std::uint64_t thunkAddress = std::uint64_t(*intRva) + std::uint64_t(t) * pointerSize;
            const std::uint64_t iatAddress = std::uint64_t(*iatRva) + std::uint64_t(t) * pointerSize;
            if (thunkAddress > std::numeric_limits<std::uint32_t>::max() ||
                iatAddress > std::numeric_limits<std::uint32_t>::max()) {
                out.warnings.push_back("delay import thunk RVA overflow");
                return;
            }

            const auto thunkOffset = mapRva(
                bytes, out.image, static_cast<std::uint32_t>(thunkAddress), pointerSize);
            if (!thunkOffset) {
                out.warnings.push_back("delay import name table leaves mapped section data");
                return;
            }
            const auto iatOffset = mapRva(
                bytes, out.image, static_cast<std::uint32_t>(iatAddress), pointerSize);
            if (!iatOffset) {
                out.warnings.push_back("delay IAT slot is outside mapped section data");
                return;
            }
            if (out.delayImports.size() >= 1'000'000) {
                out.warnings.push_back("delay import symbol count exceeds safety limit");
                return;
            }

            std::uint64_t value = 0;
            if (out.image.is64) {
                if (!readU64(reader, *thunkOffset, value)) {
                    out.warnings.push_back("truncated 64-bit delay import thunk");
                    return;
                }
            } else {
                std::uint32_t value32 = 0;
                if (!readU32(reader, *thunkOffset, value32)) {
                    out.warnings.push_back("truncated 32-bit delay import thunk");
                    return;
                }
                value = value32;
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
                symbol.ordinal = static_cast<std::uint16_t>(value & 0xffffu);
                symbol.name = "#" + std::to_string(symbol.ordinal);
            } else {
                if (value > std::numeric_limits<std::uint32_t>::max()) {
                    out.warnings.push_back("delay import name thunk is outside RVA range");
                    return;
                }
                const auto importByNameRva = delayFieldToRva(
                    static_cast<std::uint32_t>(value), rvaBased, out.image);
                if (!importByNameRva || *importByNameRva > std::numeric_limits<std::uint32_t>::max() - 2u) {
                    out.warnings.push_back("delay import hint/name RVA is invalid");
                    return;
                }
                const auto hintOffset = mapRva(bytes, out.image, *importByNameRva, 2);
                if (!hintOffset) {
                    out.warnings.push_back("delay import hint/name entry is outside section data");
                    return;
                }
                const auto name = readString(
                    bytes, out.image, static_cast<std::uint32_t>(*importByNameRva + 2u));
                if (!name) {
                    out.warnings.push_back("delay import symbol name is invalid or unterminated");
                    return;
                }
                symbol.name = *name;
            }
            out.delayImports.push_back(std::move(symbol));
        }

        if (!thunkTerminated) {
            out.warnings.push_back("delay import thunk table has no null terminator");
            return;
        }
    }

    if (!foundTerminator)
        out.warnings.push_back("delay import descriptor table has no null terminator");
}

void parseExports(std::span<const std::uint8_t> bytes, PEExtendedInfo& out) {
    const auto& directory = out.directories[0];
    if (!directory.present()) return;
    if (directory.size < 40) { out.warnings.push_back("export directory is smaller than IMAGE_EXPORT_DIRECTORY"); return; }
    const auto offset = mapRva(bytes, out.image, directory.rva, 40);
    if (!offset) { out.warnings.push_back("export directory is outside mapped section data"); return; }
    BinaryReader reader(bytes);
    std::uint32_t ordinalBase=0, functionCount=0, nameCount=0, functionsRva=0, namesRva=0, ordinalsRva=0;
    if (!readU32(reader,*offset+16,ordinalBase) || !readU32(reader,*offset+20,functionCount) ||
        !readU32(reader,*offset+24,nameCount) || !readU32(reader,*offset+28,functionsRva) ||
        !readU32(reader,*offset+32,namesRva) || !readU32(reader,*offset+36,ordinalsRva)) {
        out.warnings.push_back("truncated export directory fields"); return;
    }
    if (functionCount > 1'000'000 || nameCount > functionCount) {
        out.warnings.push_back("export table counts exceed safety limits"); return;
    }
    if (functionCount == 0) return;
    const auto functionTable = mapRva(bytes,out.image,functionsRva,std::size_t(functionCount)*4);
    const auto nameTable = nameCount ? mapRva(bytes,out.image,namesRva,std::size_t(nameCount)*4) : std::optional<std::size_t>{0};
    const auto ordinalTable = nameCount ? mapRva(bytes,out.image,ordinalsRva,std::size_t(nameCount)*2) : std::optional<std::size_t>{0};
    if (!functionTable || !nameTable || !ordinalTable) {
        out.warnings.push_back("export address/name table is outside section data"); return;
    }
    std::vector<std::string> names(functionCount);
    for (std::uint32_t i=0;i<nameCount;++i) {
        std::uint32_t nameRva=0; std::uint16_t index=0;
        if (!readU32(reader,*nameTable+std::size_t(i)*4,nameRva) ||
            !readU16(reader,*ordinalTable+std::size_t(i)*2,index) || index>=functionCount) {
            out.warnings.push_back("invalid export name ordinal"); continue;
        }
        const auto name=readString(bytes,out.image,nameRva);
        if (name) names[index]=*name;
        else out.warnings.push_back("unterminated or unmapped export name");
    }
    for (std::uint32_t i=0;i<functionCount;++i) {
        std::uint32_t functionRva=0;
        if (!readU32(reader,*functionTable+std::size_t(i)*4,functionRva)) break;
        if (functionRva==0) continue;
        PEExportSymbol symbol;
        symbol.name=std::move(names[i]);
        symbol.ordinal=ordinalBase+i;
        symbol.rva=functionRva;
        const std::uint64_t exportEnd=std::uint64_t(directory.rva)+directory.size;
        if (functionRva>=directory.rva && functionRva<exportEnd) {
            symbol.forwarded=true;
            const auto forwarder=readString(bytes,out.image,functionRva);
            if (forwarder) symbol.forwarder=*forwarder;
            else out.warnings.push_back("invalid forwarded export string");
        }
        out.exports.push_back(std::move(symbol));
    }
}

void parseRelocations(std::span<const std::uint8_t> bytes, PEExtendedInfo& out) {
    const auto& directory=out.directories[5];
    if (!directory.present()) return;
    const auto start=mapRva(bytes,out.image,directory.rva,directory.size);
    if (!start) { out.warnings.push_back("base relocation directory is outside section data"); return; }
    BinaryReader reader(bytes);
    std::size_t cursor=*start, remaining=directory.size;
    while (remaining>=8) {
        std::uint32_t pageRva=0, blockSize=0;
        if (!readU32(reader,cursor,pageRva) || !readU32(reader,cursor+4,blockSize) ||
            blockSize<8 || blockSize>remaining || ((blockSize-8)&1u)!=0) {
            out.warnings.push_back("invalid base relocation block"); return;
        }
        const std::size_t entries=(blockSize-8)/2;
        if (out.relocations.size()+entries>2'000'000) {
            out.warnings.push_back("base relocation count exceeds safety limit"); return;
        }
        for (std::size_t i=0;i<entries;++i) {
            std::uint16_t raw=0;
            if (!readU16(reader,cursor+8+i*2,raw)) { out.warnings.push_back("truncated relocation entry"); return; }
            const auto type=static_cast<std::uint8_t>(raw>>12);
            const auto offset=static_cast<std::uint32_t>(raw&0x0fff);
            if (type==0) continue;
            if (pageRva>std::numeric_limits<std::uint32_t>::max()-offset) {
                out.warnings.push_back("relocation target RVA overflow"); continue;
            }
            out.relocations.push_back({pageRva,pageRva+offset,type});
        }
        cursor+=blockSize;
        remaining-=blockSize;
    }
    if (remaining!=0) out.warnings.push_back("trailing bytes in base relocation directory");
}

void parseCertificates(std::span<const std::uint8_t> bytes, PEExtendedInfo& out) {
    const auto& directory = out.directories[4];
    if (!directory.present()) return;
    const std::uint64_t start = directory.rva; // Security directory uses a file offset, not an RVA.
    if (start > bytes.size() || directory.size > bytes.size() - static_cast<std::size_t>(start)) {
        out.warnings.push_back("certificate table points outside file bounds");
        return;
    }
    BinaryReader reader(bytes);
    std::size_t cursor = static_cast<std::size_t>(start);
    std::size_t remaining = directory.size;
    while (remaining >= 8) {
        PECertificateEntry item;
        if (!readU32(reader, cursor, item.length) ||
            !readU16(reader, cursor + 4, item.revision) ||
            !readU16(reader, cursor + 6, item.certificateType) ||
            item.length < 8 || item.length > remaining) {
            out.warnings.push_back("invalid WIN_CERTIFICATE record");
            return;
        }
        item.fileOffset = static_cast<std::uint32_t>(cursor);
        out.certificates.push_back(item);
        const std::size_t alignedLength = (std::size_t(item.length) + 7u) & ~std::size_t(7u);
        if (alignedLength > remaining) {
            if (item.length != remaining)
                out.warnings.push_back("certificate alignment exceeds remaining table size");
            return;
        }
        cursor += alignedLength;
        remaining -= alignedLength;
    }
    if (remaining != 0) out.warnings.push_back("trailing bytes in certificate table");
}

void parseDebug(std::span<const std::uint8_t> bytes, PEExtendedInfo& out) {
    const auto& directory=out.directories[6];
    if (!directory.present()) return;
    if (directory.size%28!=0) out.warnings.push_back("debug directory size is not a multiple of 28");
    const auto count=directory.size/28;
    if (count>65536) { out.warnings.push_back("debug entry count exceeds safety limit"); return; }
    const auto offset=mapRva(bytes,out.image,directory.rva,count*28);
    if (!offset) { out.warnings.push_back("debug directory is outside section data"); return; }
    BinaryReader reader(bytes);
    for (std::size_t i=0;i<count;++i) {
        const auto p=*offset+i*28;
        PEDebugEntry item;
        if (!readU32(reader,p+4,item.timestamp) || !readU32(reader,p+12,item.type) ||
            !readU32(reader,p+16,item.sizeOfData) || !readU32(reader,p+20,item.addressOfRawData) ||
            !readU32(reader,p+24,item.pointerToRawData)) {
            out.warnings.push_back("truncated IMAGE_DEBUG_DIRECTORY record"); return;
        }
        if (item.pointerToRawData>bytes.size() ||
            item.sizeOfData>bytes.size()-item.pointerToRawData)
            out.warnings.push_back("debug payload points outside file");
        out.debugEntries.push_back(item);
    }
}

void parseTls(std::span<const std::uint8_t> bytes, PEExtendedInfo& out) {
    const auto& directory=out.directories[9];
    if (!directory.present()) return;
    const std::size_t required=out.image.is64?40:24;
    const auto offset=mapRva(bytes,out.image,directory.rva,required);
    if (!offset) { out.warnings.push_back("TLS directory is outside section data"); return; }
    BinaryReader reader(bytes);
    std::uint64_t start=0,end=0,index=0,callbacks=0;
    std::uint32_t zeroFill=0,characteristics=0;
    bool ok=false;
    if (out.image.is64) {
        ok=readU64(reader,*offset,start)&&readU64(reader,*offset+8,end)&&
           readU64(reader,*offset+16,index)&&readU64(reader,*offset+24,callbacks)&&
           readU32(reader,*offset+32,zeroFill)&&readU32(reader,*offset+36,characteristics);
    } else {
        std::uint32_t a=0,b=0,c=0,d=0;
        ok=readU32(reader,*offset,a)&&readU32(reader,*offset+4,b)&&
           readU32(reader,*offset+8,c)&&readU32(reader,*offset+12,d)&&
           readU32(reader,*offset+16,zeroFill)&&readU32(reader,*offset+20,characteristics);
        start=a; end=b; index=c; callbacks=d;
    }
    if (!ok) { out.warnings.push_back("truncated TLS directory"); return; }
    out.tls.startAddressOfRawData=start; out.tls.endAddressOfRawData=end;
    out.tls.addressOfIndex=index; out.tls.addressOfCallbacks=callbacks;
    out.tls.sizeOfZeroFill=zeroFill; out.tls.characteristics=characteristics;
    if (callbacks==0) return;
    if (callbacks<out.image.imageBase || callbacks-out.image.imageBase>0xffffffffu) {
        out.warnings.push_back("TLS callback VA cannot be converted to an image RVA"); return;
    }
    const auto callbackRva=static_cast<std::uint32_t>(callbacks-out.image.imageBase);
    const std::size_t pointerSize=out.image.is64?8:4;
    for (std::size_t i=0;i<4096;++i) {
        const std::uint64_t current=std::uint64_t(callbackRva)+i*pointerSize;
        if (current>0xffffffffu) { out.warnings.push_back("TLS callback array RVA overflow"); return; }
        const auto entryOffset=mapRva(bytes,out.image,static_cast<std::uint32_t>(current),pointerSize);
        if (!entryOffset) { out.warnings.push_back("TLS callback array leaves mapped section data"); return; }
        std::uint64_t callbackVa=0;
        if (out.image.is64) { if (!readU64(reader,*entryOffset,callbackVa)) return; }
        else { std::uint32_t value=0; if (!readU32(reader,*entryOffset,value)) return; callbackVa=value; }
        if (callbackVa==0) return;
        if (callbackVa<out.image.imageBase || callbackVa-out.image.imageBase>0xffffffffu) {
            out.warnings.push_back("TLS callback VA is outside image RVA range"); continue;
        }
        out.tls.callbackRvas.push_back(static_cast<std::uint32_t>(callbackVa-out.image.imageBase));
    }
    out.warnings.push_back("TLS callback list reached safety limit without a terminator");
}

} // namespace

Result<PEExtendedInfo> parsePEExtended(std::span<const std::uint8_t> bytes) {
    auto base=parsePE(bytes);
    if (!base) return Result<PEExtendedInfo>::failure(base.error());
    PEExtendedInfo out;
    out.image=std::move(base.value());

    BinaryReader reader(bytes);
    std::uint32_t peOffset=0;
    std::uint16_t optionalSize=0, coffCharacteristics=0;
    if (!readU32(reader,0x3c,peOffset) ||
        !readU16(reader,std::size_t(peOffset)+22,coffCharacteristics) ||
        !readU16(reader,std::size_t(peOffset)+20,optionalSize))
        return Result<PEExtendedInfo>::failure("truncated PE/COFF metadata");
    out.characteristics=coffCharacteristics;
    const std::size_t optional=std::size_t(peOffset)+24;
    const std::size_t numberOffset=out.image.is64?108:92;
    const std::size_t directoryOffset=out.image.is64?112:96;
    std::uint32_t numberOfDirectories=0;
    if (optionalSize>=numberOffset+4) readU32(reader,optional+numberOffset,numberOfDirectories);
    if (optionalSize>=60) readU32(reader,optional+56,out.sizeOfImage);
    if (optionalSize>=64) readU32(reader,optional+60,out.sizeOfHeaders);
    if (optionalSize>=68) readU32(reader,optional+64,out.checksum);
    if (optionalSize>=72) {
        readU16(reader,optional+68,out.subsystem);
        readU16(reader,optional+70,out.dllCharacteristics);
    }
    const auto available=(optionalSize>directoryOffset)?(optionalSize-directoryOffset)/8:0;
    const auto count=std::min<std::uint32_t>({numberOfDirectories,16u,static_cast<std::uint32_t>(available)});
    for (std::uint32_t i=0;i<count;++i) {
        readU32(reader,optional+directoryOffset+std::size_t(i)*8,out.directories[i].rva);
        readU32(reader,optional+directoryOffset+std::size_t(i)*8+4,out.directories[i].size);
        out.directories[i].usesFileOffset = (i == 4);
    }
    parseExports(bytes,out);
    parseDelayImports(bytes,out);
    parseCertificates(bytes,out);
    parseRelocations(bytes,out);
    parseDebug(bytes,out);
    parseTls(bytes,out);
    return Result<PEExtendedInfo>::success(std::move(out));
}

} // namespace lulz
