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
struct MachOSymbolTableOfContentsEntry { std::uint32_t moduleIndex=0; std::uint32_t symbolIndex=0; };
struct MachOExternalReference { std::uint32_t symbolIndex=0; std::uint8_t flags=0; };
struct MachOInitTermPointer { std::uint64_t address=0; std::uint64_t target=0; bool initializer=false; };
struct MachOTwoLevelHint { std::uint8_t subImage=0; std::uint32_t tableOfContentsIndex=0; };
struct MachOCodeSignatureBlob { std::uint32_t slotType=0; std::uint32_t magic=0; std::uint32_t length=0; std::uint32_t offset=0; };
struct MachORebaseEntry { std::uint32_t segmentIndex=0; std::uint8_t type=0; std::uint64_t segmentOffset=0; std::uint64_t address=0; std::uint64_t fileOffset=0; };
enum class MachODyldStreamKind { Rebase, Bind, WeakBind, LazyBind, Export };
struct MachOBindEntry { std::uint32_t segmentIndex=0; std::uint8_t type=0; std::int32_t libraryOrdinal=0; std::uint8_t symbolFlags=0; std::string symbolName; std::int64_t addend=0; std::uint64_t segmentOffset=0; std::uint64_t address=0; std::uint64_t fileOffset=0; MachODyldStreamKind streamKind=MachODyldStreamKind::Bind; };
struct MachOExportEntry { std::string name; std::uint64_t flags=0; std::uint64_t address=0; std::uint64_t other=0; std::uint64_t resolver=0; std::string importedName; };
struct MachODyldStream { MachODyldStreamKind kind=MachODyldStreamKind::Rebase; std::uint32_t offset=0; std::uint32_t size=0; };
struct MachOModule {
    std::string name;
    std::uint32_t externalSymbolIndex=0, externalSymbolCount=0;
    std::uint32_t referenceSymbolIndex=0, referenceSymbolCount=0;
    std::uint32_t localSymbolIndex=0, localSymbolCount=0;
    std::uint32_t externalRelocationIndex=0, externalRelocationCount=0;
    std::uint32_t initTermIndex=0, initTermCount=0;
    std::uint32_t objcModuleInfoSize=0;
    std::uint64_t objcModuleInfoAddress=0;
};
struct Relocation { std::int32_t address=0; std::uint32_t symbolNumber=0; std::uint32_t value=0; std::uint8_t type=0; std::uint8_t length=0; bool pcRelative=false; bool external=false; bool scattered=false; };
struct FormatInfo { Format format=Format::Unknown; bool valid=false; bool is64Bit=false; std::uint64_t imageBase=0, entryPoint=0, entryFileOffset=0, entryStackSize=0; std::uint32_t architecture=0, architectureSubtype=0, fileType=0; std::vector<Section> sections; std::vector<DataDirectory> directories; std::uint32_t localSymbolIndex=0, localSymbolCount=0, externalSymbolIndex=0, externalSymbolCount=0, undefinedSymbolIndex=0, undefinedSymbolCount=0; std::vector<Symbol> symbols; std::vector<std::uint32_t> indirectSymbols; std::vector<MachOSymbolTableOfContentsEntry> symbolTableOfContents; std::vector<MachOExternalReference> externalReferences; std::vector<MachOInitTermPointer> initTermPointers; std::vector<MachOTwoLevelHint> twoLevelHints; std::uint32_t codeSignatureOffset=0, codeSignatureSize=0, codeSignatureMagic=0; std::vector<MachOCodeSignatureBlob> codeSignatureBlobs; std::vector<MachORebaseEntry> rebases; std::vector<MachOBindEntry> binds; std::vector<MachOExportEntry> exports; std::vector<MachODyldStream> dyldStreams; std::vector<MachOModule> modules; std::vector<Relocation> relocations; ValidationReport diagnostics; };
FormatInfo analyzeFormat(const BinaryImage&);
std::optional<std::uint64_t> rvaToOffset(const FormatInfo&,std::uint64_t);
std::optional<std::uint64_t> offsetToRva(const FormatInfo&,std::uint64_t);
std::optional<std::uint64_t> vaToRva(const FormatInfo&,std::uint64_t);
std::vector<EmbeddedPayload> detectEmbeddedPayloads(const BinaryImage&);
}
