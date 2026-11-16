#include "lulz/asm/x86/X86Decoder.hpp"
#include "lulz/asm/x86/X86Encoder.hpp"
#include "lulz/binary/BinaryReader.hpp"
#include "lulz/hex/HexParser.hpp"
#include "lulz/analysis/EntropyAnalyzer.hpp"
#include "lulz/formats/pe/PEParser.hpp"
#include "lulz/formats/pe/PEExtendedParser.hpp"
#include "lulz/formats/pe/UnwindInfo.hpp"
#include "lulz/analysis/FunctionAnalysis.hpp"
#include <array>
#include <cassert>
#include <iostream>
int main() {
    auto h=lulz::parseHex("48 89 D8 C3");
    assert(h && h.value().size()==4 && h.value()[0]==0x48);
    assert(!lulz::parseHex("2g43"));
    auto a=lulz::assembleX86Subset("mov rax, rbx");
    assert(a && a.value().size()==3);
    auto d=lulz::disassembleX86Subset(a.value());
    assert(d.size()==1 && d[0].text=="mov rax, rbx");
    std::array<std::uint8_t,4> data{0,0,0,0};
    lulz::BinaryReader r(data);
    assert(r.u32le(0) && r.u32le(0).value()==0);
    assert(!r.u32le(1));
    assert(lulz::shannonEntropy(data)==0.0);

    // Minimal PE32+ image with one x64 RUNTIME_FUNCTION entry in .pdata.
    std::vector<std::uint8_t> pe(0x500, 0);
    auto w16=[&](std::size_t o, std::uint16_t v) { pe[o]=std::uint8_t(v); pe[o+1]=std::uint8_t(v>>8); };
    auto w32=[&](std::size_t o, std::uint32_t v) { for(int n=0;n<4;++n) pe[o+n]=std::uint8_t(v>>(n*8)); };
    w16(0, 0x5a4d); w32(0x3c, 0x80); w32(0x80, 0x00004550);
    w16(0x84, 0x8664); w16(0x86, 1); w16(0x94, 240); w16(0x98, 0x20b);
    w32(0x98+108, 16); w32(0x98+112+3*8, 0x1000); w32(0x98+112+3*8+4, 12);
// Security directory (index 4) stores a file offset, not an RVA.
// Append one aligned WIN_CERTIFICATE record after the section data.
pe.resize(0x510, 0);
w32(0x98+112+4*8, 0x500); w32(0x98+112+4*8+4, 16);
w32(0x500, 12); w16(0x504, 0x0200); w16(0x506, 2);
    const std::size_t sh=0x98+240;
    pe[sh]='.'; pe[sh+1]='p'; pe[sh+2]='d'; pe[sh+3]='a'; pe[sh+4]='t'; pe[sh+5]='a';
    w32(sh+8, 0x300); w32(sh+12, 0x1000); w32(sh+16, 0x300); w32(sh+20, 0x200);
    w32(0x200, 0x1100); w32(0x204, 0x1150); w32(0x208, 0x1200);
    // UNWIND_INFO at RVA 0x1200: version 1, one UWOP_ALLOC_SMALL (32 bytes).
    pe[0x400]=0x01; pe[0x401]=4; pe[0x402]=1; pe[0x403]=0;
    pe[0x404]=4; pe[0x405]=0x32;
    auto parsed=lulz::parsePE(pe);
    assert(parsed && parsed.value().is64);
    auto extended = lulz::parsePEExtended(pe);
    assert(extended && extended.value().image.is64);
    assert(extended.value().directories[3].rva == 0x1000);
    assert(extended.value().directories[3].size == 12);
    assert(extended.value().directories[4].usesFileOffset);
    assert(extended.value().certificates.size() == 1);
    assert(extended.value().certificates[0].certificateType == 2);

    // A second section holds a synthetic RVA-based delay import directory.
    auto delayPe = pe;
    delayPe.resize(0x800, 0);
    auto dw16 = [&](std::size_t o, std::uint16_t v) {
        delayPe[o] = std::uint8_t(v);
        delayPe[o + 1] = std::uint8_t(v >> 8);
    };
    auto dw32 = [&](std::size_t o, std::uint32_t v) {
        for (int n = 0; n < 4; ++n) delayPe[o + n] = std::uint8_t(v >> (n * 8));
    };
    dw16(0x86, 2);
    const std::size_t delaySection = sh + 40;
    delayPe[delaySection] = '.';
    delayPe[delaySection + 1] = 'd';
    delayPe[delaySection + 2] = 'i';
    delayPe[delaySection + 3] = 'd';
    delayPe[delaySection + 4] = 'a';
    delayPe[delaySection + 5] = 't';
    dw32(delaySection + 8, 0x200);
    dw32(delaySection + 12, 0x2000);
    dw32(delaySection + 16, 0x200);
    dw32(delaySection + 20, 0x600);
    dw32(delaySection + 36, 0x40000040);
    const std::size_t delayDirectoryEntry = 0x98 + 112 + 13 * 8;
    dw32(delayDirectoryEntry, 0x2000);
    dw32(delayDirectoryEntry + 4, 64);
    // ImgDelayDescr: grAttrs=RVA, name=0x2040, IAT=0x2070, INT=0x2060.
    dw32(0x600, 1);
    dw32(0x604, 0x2040);
    dw32(0x60c, 0x2088);
    dw32(0x610, 0x2060);
    // The second 32-byte descriptor is the required null terminator.
    const char delayModule[] = "delaytest.dll";
    for (std::size_t i = 0; i < sizeof(delayModule); ++i)
        delayPe[0x640 + i] = static_cast<std::uint8_t>(delayModule[i]);
    // IMAGE_THUNK_DATA64: one name import, one ordinal import (#42), then zero.
    auto dw64 = [&](std::size_t o, std::uint64_t v) {
        for (int n = 0; n < 8; ++n) delayPe[o + n] = std::uint8_t(v >> (n * 8));
    };
    dw64(0x660, 0x20a0);
    dw64(0x668, 0x800000000000002aull);
    dw64(0x670, 0);
    dw16(0x6a0, 7); // hint
    const char delayName[] = "DelayFunc";
    for (std::size_t i = 0; i < sizeof(delayName); ++i)
        delayPe[0x6a2 + i] = static_cast<std::uint8_t>(delayName[i]);

    auto delayParsed = lulz::parsePE(delayPe);
    assert(delayParsed && delayParsed.value().sectionCount == 2);
    auto delayExtended = lulz::parsePEExtended(delayPe);
    assert(delayExtended);
    assert(delayExtended.value().directories[13].rva == 0x2000);
    assert(delayExtended.value().delayImports.size() == 2);
    assert(delayExtended.value().delayImports[0].module == "delaytest.dll");
    assert(delayExtended.value().delayImports[0].name == "DelayFunc");
    assert(delayExtended.value().delayImports[0].iatRva == 0x2088);
    assert(!delayExtended.value().delayImports[0].byOrdinal);
    assert(delayExtended.value().delayImports[1].byOrdinal);
    assert(delayExtended.value().delayImports[1].ordinal == 42);
    assert(delayExtended.value().delayImports[1].name == "#42");

    // A call through the delay-IAT slot must resolve to the delay import metadata.
    delayPe[0x300] = 0xff;
    delayPe[0x301] = 0x15;
    delayPe[0x302] = 0x82; // 0x2088 - (0x1100 + 6) = 0x0f82
    delayPe[0x303] = 0x0f;
    delayPe[0x304] = 0;
    delayPe[0x305] = 0;
    auto delayAnalysis = lulz::analyzePEFunctions(delayPe, delayParsed.value());
    assert(delayAnalysis && delayAnalysis.value().functions.size() == 1);
    assert(delayAnalysis.value().functions[0].calls.size() == 1);
    assert(delayAnalysis.value().functions[0].calls[0].resolved);
    assert(delayAnalysis.value().functions[0].calls[0].target == "delaytest.dll!DelayFunc");
    const auto delayJson = lulz::functionAnalysisToJson(delayAnalysis.value(), delayParsed.value());
    assert(delayJson.find("\"delay_imports\"") != std::string::npos);
    assert(delayJson.find("DelayFunc") != std::string::npos);

    // Malformed delay descriptor addresses are reported without crashing.
    auto malformedDelayPe = delayPe;
    malformedDelayPe[0x604] = 0xff;
    malformedDelayPe[0x605] = 0xff;
    malformedDelayPe[0x606] = 0xff;
    malformedDelayPe[0x607] = 0xff;
    auto malformedDelay = lulz::parsePEExtended(malformedDelayPe);
    assert(malformedDelay);
    assert(malformedDelay.value().delayImports.empty());
    assert(!malformedDelay.value().warnings.empty());
    auto runtime=lulz::parsePEExceptionDirectory(pe, parsed.value());
    assert(runtime && runtime.value().size()==1);
    assert(runtime.value()[0].beginRva==0x1100);
    assert(runtime.value()[0].endRva==0x1150);
    assert(runtime.value()[0].unwindInfoRva==0x1200);
    auto unwind=lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]);
    assert(unwind && unwind.value().version==1);
    assert(unwind.value().stackAllocation==32);
    assert(unwind.value().operations.size()==1);
    assert(unwind.value().operations[0].name=="UWOP_ALLOC_SMALL");
    assert(unwind.value().explicitAllocation==32);

    // Function analysis consumes .pdata/.xdata and emits direct-call graph edges.
    pe[0x300]=0xe8; pe[0x301]=0x0b; pe[0x302]=0; pe[0x303]=0; pe[0x304]=0; // call 0x1110
    auto fa=lulz::analyzePEFunctions(pe,parsed.value());
    assert(fa && fa.value().functions.size()==1);
    assert(!fa.value().functions[0].calls.empty());
    assert(fa.value().functions[0].calls[0].kind=="call_rel32");
    assert(fa.value().functions[0].calls.size()==1);
    // An E8 byte inside a MOV immediate is data, not a second CALL instruction.
    pe[0x305]=0x48; pe[0x306]=0xb8; pe[0x307]=0xe8; pe[0x308]=0x11;
    pe[0x309]=0; pe[0x30a]=0; pe[0x30b]=0; pe[0x30c]=0; pe[0x30d]=0; pe[0x30e]=0;
    auto decodedAgain=lulz::analyzePEFunctions(pe,parsed.value());
    assert(decodedAgain && decodedAgain.value().functions[0].calls.size()==1);
    assert(fa.value().functions[0].calls[0].resolved);

    // A RIP-relative indirect call to an ordinary section slot is not automatically an IAT call.
    // RVA 0x12f0 is inside the section but is absent from the import directory.
    pe[0x300]=0xff; pe[0x301]=0x15;
    pe[0x302]=0xea; pe[0x303]=0x01; pe[0x304]=0; pe[0x305]=0; // call [rip + 0x1ea] -> RVA 0x12f0
    auto indirect=lulz::analyzePEFunctions(pe,parsed.value());
    assert(indirect && indirect.value().functions.size()==1);
    assert(indirect.value().functions[0].calls.size()==1);
    const auto& indirectCall=indirect.value().functions[0].calls[0];
    assert(indirectCall.kind=="call_indirect_rip");
    assert(indirectCall.targetRva==0x12f0);
    assert(!indirectCall.resolved);
    assert(indirectCall.target.find("indirect memory slot")!=std::string::npos);
    assert(indirectCall.target.find("IAT[")==std::string::npos);

    const auto json=lulz::functionAnalysisToJson(fa.value(),parsed.value());
    assert(json.find("call_graph")!=std::string::npos);
    assert(json.find("pe_metadata")!=std::string::npos);
    assert(json.find("analysis_warnings")!=std::string::npos);
    assert(json.find("begin_rva")!=std::string::npos);

    // PUSH_NONVOL contributes one pointer-sized slot and records the register.
    pe[0x400]=0x01; pe[0x401]=4; pe[0x402]=1; pe[0x403]=0;
    pe[0x404]=4; pe[0x405]=0x50; // UWOP_PUSH_NONVOL RBP
    auto push=lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]);
    assert(push && push.value().stackAllocation==8);
    assert(push.value().savedRegisters.size()==1 && push.value().savedRegisters[0]=="RBP");

    // SAVE_NONVOL RBX, stack offset 2 * 8 = 16 bytes.
    pe[0x402]=2; pe[0x404]=4; pe[0x405]=0x34; pe[0x406]=2; pe[0x407]=0;
    auto save=lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]);
    assert(save && save.value().operations.size()==1);
    assert(save.value().operations[0].name=="UWOP_SAVE_NONVOL");
    assert(save.value().operations[0].value==16 && save.value().savedRegisters[0]=="RBX");

    // SAVE_XMM128 uses 16-byte scaling and is reported separately from GPR saves.
    pe[0x402]=2; pe[0x404]=4; pe[0x405]=0x68; pe[0x406]=2; pe[0x407]=0;
    auto xmm=lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]);
    assert(xmm && xmm.value().savedXmmRegisters.size()==1);
    assert(xmm.value().savedXmmRegisters[0]=="XMM6");
    assert(xmm.value().operations[0].value==32);

    // ALLOC_LARGE OpInfo=0: the next slot is scaled by eight.
    pe[0x402]=2; pe[0x404]=4; pe[0x405]=0x01; pe[0x406]=16; pe[0x407]=0;
    auto large=lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]);
    assert(large && large.value().stackAllocation==128);

    // CHAININFO tail contains another 12-byte RUNTIME_FUNCTION record.
    pe[0x400]=0x21; pe[0x401]=0; pe[0x402]=0; pe[0x403]=0;
    w32(0x404,0x1100); w32(0x408,0x1150); w32(0x40c,0x1200);
    auto chain=lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]);
    assert(chain && chain.value().chained);
    assert(chain.value().chainedFunction.beginRva==0x1100);

    // EHANDLER tail stores a handler RVA.
    pe[0x400]=0x09; pe[0x401]=0; pe[0x402]=0; pe[0x403]=0;
    w32(0x404,0x1100);
    auto handler=lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]);
    assert(handler && handler.value().hasExceptionHandler && handler.value().handlerRva==0x1100);

    // Corrupt handler RVA and truncated input must fail safely.
    w32(0x404,0xffffffff);
    assert(!lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]));
    assert(!lulz::parsePEUnwindInfo(std::span<const std::uint8_t>(pe.data(),0x402),parsed.value(),runtime.value()[0]));

    // Reject volatile GPRs in operations that must save nonvolatile registers.
    pe[0x400]=0x01; pe[0x401]=4; pe[0x402]=1; pe[0x403]=0;
    pe[0x404]=4; pe[0x405]=0x10; // UWOP_PUSH_NONVOL RAX (invalid)
    assert(!lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]));

    // XMM save operations may only name the nonvolatile XMM6-XMM15 range.
    pe[0x402]=2; pe[0x404]=4; pe[0x405]=0x08; // UWOP_SAVE_XMM128 XMM0
    pe[0x406]=0; pe[0x407]=0;
    assert(!lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]));

    // Frame register must be a nonvolatile GPR; RAX is not valid.
    pe[0x400]=0x01; pe[0x401]=4; pe[0x402]=0; pe[0x403]=1;
    assert(!lulz::parsePEUnwindInfo(pe,parsed.value(),runtime.value()[0]));

    // A malformed individual unwind record must not abort the entire image analysis.
    auto bestEffort = lulz::analyzePEFunctions(pe, parsed.value());
    assert(bestEffort);
    assert(bestEffort.value().functions.empty());
    assert(!bestEffort.value().warnings.empty());

    // Images without .pdata still produce a successful partial analysis result.
    auto withoutPdata = pe;
    auto w32copy = [&](std::size_t o, std::uint32_t v) {
        for (int n = 0; n < 4; ++n) withoutPdata[o + n] = std::uint8_t(v >> (n * 8));
    };
    w32copy(0x98 + 112 + 3 * 8, 0);
    w32copy(0x98 + 112 + 3 * 8 + 4, 0);
    auto noPdataInfo = lulz::parsePE(withoutPdata);
    assert(noPdataInfo);
    auto noPdataAnalysis = lulz::analyzePEFunctions(withoutPdata, noPdataInfo.value());
    assert(noPdataAnalysis);
    assert(noPdataAnalysis.value().functions.empty());
    assert(!noPdataAnalysis.value().warnings.empty());

    std::cout<<"All foundation tests passed\n";
}
