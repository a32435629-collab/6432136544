#include "lulz/analysis/FunctionAnalysis.hpp"
#include "lulz/binary/BinaryReader.hpp"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>

namespace lulz {
namespace {
Result<std::size_t> mapRva(std::uint32_t rva, std::size_t len, const PEInfo& pe, std::size_t fileSize) {
    for (const auto& s : pe.sections) {
        const std::uint64_t span=std::max(s.virtualSize,s.rawSize), start=s.virtualAddress;
        if (rva<start || std::uint64_t(rva)-start>=span) continue;
        const std::uint64_t delta=std::uint64_t(rva)-start;
        if (delta>s.rawSize || len>s.rawSize-delta) return Result<std::size_t>::failure("RVA exceeds section raw data");
        const std::uint64_t off=std::uint64_t(s.rawOffset)+delta;
        if (off>fileSize || len>fileSize-off) return Result<std::size_t>::failure("RVA exceeds file bounds");
        return Result<std::size_t>::success(static_cast<std::size_t>(off));
    }
    return Result<std::size_t>::failure("RVA is not backed by a section");
}
std::string hex32(std::uint32_t v) { std::ostringstream o; o<<"0x"<<std::hex<<v; return o.str(); }
std::string hex64(std::uint64_t v) { std::ostringstream o; o<<"0x"<<std::hex<<v; return o.str(); }
std::string frameRegName(unsigned n) {
    static const char* names[]={"none","","","RBX","RSP","RBP","RSI","RDI","R8","R9","R10","R11","R12","R13","R14","R15"};
    return n<16?names[n]:"unknown";
}
std::string escapeJson(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c:s) { if(c=='"') o<<"\\\""; else if(c=='\\') o<<"\\\\"; else if(c=='\n') o<<"\\n"; else if(c=='\r') o<<"\\r"; else if(c=='\t') o<<"\\t"; else if(c<0x20) o<<"?"; else o<<c; }
    return o.str();
}
const AnalyzedFunction* containing(const std::vector<AnalyzedFunction>& fs, std::uint32_t rva) {
    auto it=std::upper_bound(fs.begin(),fs.end(),rva,[](std::uint32_t x,const AnalyzedFunction& f){return x<f.range.beginRva;});
    if(it==fs.begin()) return nullptr;
    --it;
    return rva>=it->range.beginRva && rva<it->range.endRva ? &*it : nullptr;
}
}

Result<FunctionAnalysis> analyzePEFunctions(std::span<const std::uint8_t> bytes, const PEInfo& pe) {
    if(!pe.is64 || pe.machine!=0x8664) return Result<FunctionAnalysis>::failure("Function Analysis Engine currently supports x64 PE32+ only");
    FunctionAnalysis result;
    for (const auto& warning : pe.warnings)
        result.warnings.push_back("PE section: " + warning);

    // Additional structural checks that require the complete section table.
    // These are diagnostics only: unusual flags/layouts are not proof of corruption.
    constexpr std::uint32_t kMemExecute = 0x20000000u;
    constexpr std::uint32_t kMemWrite = 0x80000000u;
    bool entryPointMapped = false;
    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        const auto& section = pe.sections[i];
        const std::uint64_t span = std::max(section.virtualSize, section.rawSize);
        const bool executable = (section.characteristics & kMemExecute) != 0;
        const bool writable = (section.characteristics & kMemWrite) != 0;
        const std::string label = section.name.empty()
            ? ("section " + std::to_string(i))
            : ("section " + section.name + " (index " + std::to_string(i) + ")");
        if (executable && writable) {
            result.warnings.push_back("PE structure: " + label +
                " is both writable and executable (W+X permissions)");
        }
        if (executable && section.rawSize == 0) {
            result.warnings.push_back("PE structure: " + label +
                " is executable but has no raw file data");
        }
        if (pe.entryPoint != 0 && span != 0 &&
            pe.entryPoint >= section.virtualAddress &&
            std::uint64_t(pe.entryPoint) - section.virtualAddress < span) {
            entryPointMapped = true;
            if (!executable) {
                result.warnings.push_back("PE structure: entry point is located in " +
                    label + ", which is not marked executable");
            }
            const std::uint64_t delta =
                std::uint64_t(pe.entryPoint) - section.virtualAddress;
            if (delta >= section.rawSize) {
                result.warnings.push_back("PE structure: entry point is in the virtual-only tail of " +
                    label + " and has no corresponding file bytes");
            }
        }
    }
    if (pe.entryPoint != 0 && !entryPointMapped) {
        result.warnings.push_back("PE structure: entry point RVA " + hex32(pe.entryPoint) +
            " is not covered by any section");
    }

    auto extendedMetadata = parsePEExtended(bytes);
    if (extendedMetadata) {
        result.peMetadata = std::move(extendedMetadata.value());
        for (const auto& warning : result.peMetadata.warnings)
            result.warnings.push_back("PE metadata: " + warning);
    } else {
        result.warnings.push_back("extended PE metadata unavailable: " + extendedMetadata.error());
    }

    auto imports=parsePEImports(bytes,pe);
    if(imports) result.imports=std::move(imports.value());
    else result.warnings.push_back("imports could not be parsed: "+imports.error());

    // A missing or damaged .pdata directory should not discard valid PE metadata.
    // Record the section containing AddressOfEntryPoint and a small byte window
    // for inspection. These bytes are never executed.
    for (const auto& section : pe.sections) {
        const std::uint64_t span = std::max(section.virtualSize, section.rawSize);
        if (pe.entryPoint < section.virtualAddress ||
            std::uint64_t(pe.entryPoint) - section.virtualAddress >= span) continue;
        result.entryPointSection = section.name.empty() ? "<unnamed>" : section.name;
        const std::uint64_t delta = std::uint64_t(pe.entryPoint) - section.virtualAddress;
        if (delta < section.rawSize) {
            const std::uint64_t fileOffset = std::uint64_t(section.rawOffset) + delta;
            if (fileOffset < bytes.size()) {
                const std::size_t count = std::min<std::size_t>(
                    32, std::min<std::uint64_t>(section.rawSize - delta, bytes.size() - fileOffset));
                result.entryPointBytes.assign(bytes.begin() + static_cast<std::size_t>(fileOffset),
                    bytes.begin() + static_cast<std::size_t>(fileOffset) + count);
            }
        }
        break;
    }
    if (!result.entryPointBytes.empty()) {
        ZydisDecoder epDecoder;
        if (ZYAN_SUCCESS(ZydisDecoderInit(&epDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
            std::size_t cursor = 0;
            while (cursor < result.entryPointBytes.size() && result.entryPointInstructions.size() < 8) {
                ZydisDecodedInstruction instruction{};
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
                const auto status = ZydisDecoderDecodeFull(&epDecoder,
                    result.entryPointBytes.data() + cursor,
                    result.entryPointBytes.size() - cursor, &instruction, operands);
                if (!ZYAN_SUCCESS(status) || instruction.length == 0) break;
                result.entryPointInstructions.emplace_back(ZydisMnemonicGetString(instruction.mnemonic));
                cursor += instruction.length;
            }
        }
    }

    auto runtime=parsePEExceptionDirectory(bytes,pe);
    if(!runtime) {
        result.warnings.push_back("function boundaries unavailable: "+runtime.error());

        // Without .pdata, do not fabricate confirmed function ranges. Scan only
        // executable sections for common x64 prologue byte patterns and expose
        // them as heuristic candidates. Limits keep hostile/huge files bounded.
        constexpr std::size_t kMaxScanBytes = 128u * 1024u * 1024u;
        constexpr std::size_t kMaxCandidates = 50000;
        std::size_t scanned = 0;
        for (const auto& section : pe.sections) {
            if ((section.characteristics & 0x20000000u) == 0 || section.rawSize < 4)
                continue;
            const std::uint64_t fileOffset = section.rawOffset;
            if (fileOffset >= bytes.size()) continue;
            const std::size_t available = std::min<std::uint64_t>(
                section.rawSize, bytes.size() - fileOffset);
            const std::size_t count = std::min(available, kMaxScanBytes - scanned);
            if (count < 4) continue;
            const auto* data = bytes.data() + static_cast<std::size_t>(fileOffset);
            for (std::size_t i = 0; i + 4 <= count &&
                 result.heuristicCandidates.size() < kMaxCandidates; ++i) {
                const auto b0=data[i], b1=data[i+1], b2=data[i+2], b3=data[i+3];
                const char* reason = nullptr;
                if (b0==0x55 && b1==0x48 && b2==0x89 && b3==0xe5)
                    reason = "push rbp; mov rbp, rsp";
                else if (b0==0x48 && b1==0x83 && b2==0xec)
                    reason = "sub rsp, imm8";
                else if (b0==0x48 && b1==0x81 && b2==0xec)
                    reason = "sub rsp, imm32";
                else if (b0==0x40 && b1==0x55)
                    reason = "REX push rbp";
                else if (b0==0x48 && b1==0x89 && b2==0x5c && b3==0x24)
                    reason = "save nonvolatile register";
                if (reason) {
                    const std::uint64_t rva = std::uint64_t(section.virtualAddress) + i;
                    if (rva <= 0xffffffffull)
                        result.heuristicCandidates.push_back({
                            static_cast<std::uint32_t>(rva), reason});
                }
            }
            scanned += count;
            if (scanned >= kMaxScanBytes ||
                result.heuristicCandidates.size() >= kMaxCandidates) break;
        }
        if (!result.heuristicCandidates.empty())
            result.warnings.push_back("heuristic function candidates found: " +
                std::to_string(result.heuristicCandidates.size()) +
                " (not confirmed; no function boundaries were inferred)");
        if (scanned >= kMaxScanBytes)
            result.warnings.push_back("heuristic scan stopped at the 128 MiB safety limit");
        if (result.heuristicCandidates.size() >= kMaxCandidates)
            result.warnings.push_back("heuristic scan stopped at the 50000-candidate safety limit");
        return Result<FunctionAnalysis>::success(std::move(result));
    }

    result.functions.reserve(runtime.value().size());
    for(const auto& fn:runtime.value()) {
        AnalyzedFunction af;
        af.range=fn;

        auto unwind=parsePEUnwindInfo(bytes,pe,fn);
        if(!unwind) {
            af.unwindValid=false;
            af.unwindError=unwind.error();
            result.warnings.push_back("UNWIND_INFO invalid for function at "+
                hex32(fn.beginRva)+" ("+hex32(fn.unwindInfoRva)+
                "); function boundaries retained: "+af.unwindError);
        } else {
            af.unwind=std::move(unwind.value());
            for (const auto& warning : af.unwind.warnings) {
                result.warnings.push_back("UNWIND_INFO at " +
                    hex32(fn.unwindInfoRva) + ": " + warning);
            }

            // A damaged chained record invalidates only chain metadata, not the
            // primary RUNTIME_FUNCTION range or the function's instruction scan.
            std::set<std::uint32_t> seen{fn.unwindInfoRva};
            auto chain=af.unwind;
            for(unsigned depth=0;chain.chained && depth<32;++depth) {
                const auto next=chain.chainedFunction;
                if(!seen.insert(next.unwindInfoRva).second) {
                    af.chainValid=false;
                    af.chainError="CHAININFO contains a cycle";
                    break;
                }
                auto nested=parsePEUnwindInfo(bytes,pe,next);
                if(!nested) {
                    af.chainValid=false;
                    af.chainError="chained UNWIND_INFO is invalid: "+nested.error();
                    break;
                }
                for (const auto& warning : nested.value().warnings) {
                    result.warnings.push_back("chained UNWIND_INFO at " +
                        hex32(next.unwindInfoRva) + ": " + warning);
                }
                af.chainedRecords.push_back(next);
                chain=std::move(nested.value());
            }
            if(af.chainValid && chain.chained) {
                af.chainValid=false;
                af.chainError="CHAININFO nesting exceeds 32 levels";
            }
            if(!af.chainValid) {
                result.warnings.push_back("function at "+hex32(fn.beginRva)+
                    " retained, but "+af.chainError);
            }
        }
        result.functions.push_back(std::move(af));
    }
    std::sort(result.functions.begin(),result.functions.end(),[](const auto& a,const auto& b){return a.range.beginRva<b.range.beginRva;});
    std::map<std::uint32_t,std::string> iat;
    for(const auto& im:result.imports) iat[im.iatRva]=im.module+"!"+im.name;
    for(const auto& im:result.peMetadata.delayImports) iat[im.iatRva]=im.module+"!"+im.name;

    // Decode complete x64 instructions. This prevents opcode-like bytes inside
    // immediates/displacements from being mistaken for CALL/JMP instructions.
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return Result<FunctionAnalysis>::failure("failed to initialize Zydis x64 decoder");
    }
    for (auto& fn : result.functions) {
        const std::uint64_t length = std::uint64_t(fn.range.endRva) - fn.range.beginRva;
        if (length > 16 * 1024 * 1024) continue;
        auto off = mapRva(fn.range.beginRva, static_cast<std::size_t>(length), pe, bytes.size());
        if (!off) continue;

        const std::size_t start = off.value();
        const std::size_t n = static_cast<std::size_t>(length);
        std::size_t cursor = 0;
        while (cursor < n) {
            ZydisDecodedInstruction instruction{};
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
            const auto status = ZydisDecoderDecodeFull(
                &decoder, bytes.data() + start + cursor, n - cursor,
                &instruction, operands);
            if (!ZYAN_SUCCESS(status) || instruction.length == 0) {
                ++result.undecodableBytes;
                ++cursor;
                continue;
            }

            const auto mnemonic = instruction.mnemonic;
            fn.instructions.push_back({
                static_cast<std::uint32_t>(std::uint64_t(fn.range.beginRva) + cursor),
                instruction.length,
                ZydisMnemonicGetString(mnemonic)
            });
            ++result.decodedInstructions;
            const bool isCall = mnemonic == ZYDIS_MNEMONIC_CALL;
            const bool isJump = mnemonic == ZYDIS_MNEMONIC_JMP;
            if ((isCall || isJump) && instruction.operand_count_visible > 0) {
                const auto& targetOperand = operands[0];
                const std::uint64_t instructionRva =
                    std::uint64_t(fn.range.beginRva) + cursor;
                const std::uint64_t instructionVa = pe.imageBase + instructionRva;
                FunctionCall call;
                call.instructionRva = static_cast<std::uint32_t>(instructionRva);

                if (targetOperand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    targetOperand.imm.is_relative) {
                    ZyanU64 targetVa = 0;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                            &instruction, &targetOperand, instructionVa, &targetVa)) &&
                        targetVa >= pe.imageBase &&
                        targetVa - pe.imageBase <= 0xffffffffull) {
                        call.targetRva = static_cast<std::uint32_t>(targetVa - pe.imageBase);
                        call.kind = isCall ? "call_rel32" : (instruction.raw.imm[0].size == 8 ? "jmp_rel8" : "jmp_rel32");
                        call.target = hex32(call.targetRva);
                        call.resolved = true;
                        fn.calls.push_back(std::move(call));
                    }
                } else if (targetOperand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                           targetOperand.mem.base == ZYDIS_REGISTER_RIP) {
                    ZyanU64 slotVa = 0;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                            &instruction, &targetOperand, instructionVa, &slotVa)) &&
                        slotVa >= pe.imageBase &&
                        slotVa - pe.imageBase <= 0xffffffffull) {
                        call.targetRva = static_cast<std::uint32_t>(slotVa - pe.imageBase);
                        call.kind = isCall ? "call_indirect_rip" : "jmp_indirect_rip";
                        const auto it = iat.find(call.targetRva);
                        if (it != iat.end()) {
                            call.target = it->second;
                            call.resolved = true;
                        } else {
                            call.target = "indirect memory slot " + hex32(call.targetRva);
                        }
                        fn.calls.push_back(std::move(call));
                    }
                }
            }
            cursor += instruction.length;
        }
    }
    // Resolve direct destinations to metadata-backed functions; imports stay separately labeled.
    for(auto& fn:result.functions) for(auto& call:fn.calls) {
        if(call.kind=="call_indirect_rip" || call.kind=="jmp_indirect_rip") { if(!call.resolved) ++result.unresolvedCalls; continue; }
        if(const auto* dest=containing(result.functions,call.targetRva)) call.target="function "+hex32(dest->range.beginRva);
        else { call.target="external/unknown "+hex32(call.targetRva); call.resolved=false; ++result.unresolvedCalls; }
    }
    return Result<FunctionAnalysis>::success(std::move(result));
}

std::string functionAnalysisToJson(const FunctionAnalysis& a,const PEInfo& pe) {
    std::ostringstream o; o<<"{\n  \"format\": \"PE32+ x64\",\n  \"image_base\": \""<<hex64(pe.imageBase)<<"\",\n  \"function_count\": "<<a.functions.size()<<",\n  \"unresolved_calls\": "<<a.unresolvedCalls<<",\n  \"function_boundary_source\": \""<<(pe.exceptionDirectoryRva && pe.exceptionDirectorySize ? "PE exception directory (.pdata)" : "heuristic candidates only; no confirmed boundaries")<<"\",\n  \"entry_point\": {\"rva\": \""<<hex32(pe.entryPoint)<<"\", \"section\": \""<<escapeJson(a.entryPointSection)<<"\", \"bytes\": \"";
    for (auto byte : a.entryPointBytes) { static const char* digits="0123456789ABCDEF"; o<<digits[byte>>4]<<digits[byte&15]; }
    o<<"\", \"instructions\": [";
    for (std::size_t i=0;i<a.entryPointInstructions.size();++i) { if(i)o<<", "; o<<"\""<<escapeJson(a.entryPointInstructions[i])<<"\""; }
    o<<"]},\n  \"heuristic_function_candidates\": [";
    for (std::size_t i=0;i<a.heuristicCandidates.size();++i) { if(i)o<<", "; o<<"{\"begin_rva\": \""<<hex32(a.heuristicCandidates[i].beginRva)<<"\", \"reason\": \""<<escapeJson(a.heuristicCandidates[i].reason)<<"\"}"; }
    o<<"],\n  \"call_scan_mode\": \"Zydis x64 instruction decoding\",\n  \"analysis_limits\": [\"Call sites are decoded instruction boundaries; indirect memory targets may remain unresolved.\", \"RIP-relative indirect calls are resolved only when their slot matches parsed ordinary or delay-import IAT metadata.\", \"Heuristic function candidates are not confirmed function boundaries.\"],\n  \"analysis_warnings\": [";
    for(std::size_t i=0;i<a.warnings.size();++i){if(i)o<<",";o<<"\n    \""<<escapeJson(a.warnings[i])<<"\"";}
    if(!a.warnings.empty()) o<<"\n  ";
    o<<"],\n  \"pe_metadata\": {\"size_of_image\": "<<a.peMetadata.sizeOfImage
     <<", \"size_of_headers\": "<<a.peMetadata.sizeOfHeaders
     <<", \"checksum\": "<<a.peMetadata.checksum
     <<", \"subsystem\": "<<a.peMetadata.subsystem
     <<", \"dll_characteristics\": "<<a.peMetadata.dllCharacteristics
     <<", \"data_directories\": [";
    bool firstDirectory=true;
    for(std::size_t i=0;i<a.peMetadata.directories.size();++i) {
        const auto& directory=a.peMetadata.directories[i];
        if(!directory.present()) continue;
        if(!firstDirectory) o<<", ";
        firstDirectory=false;
        o<<"{\"index\": "<<i<<", \"address_kind\": \""<<(directory.usesFileOffset?"file_offset":"rva")<<"\", \"address\": \""<<hex32(directory.rva)<<"\", \"size\": "<<directory.size<<"}";
    }
    o<<"], \"exports\": [";
    for(std::size_t i=0;i<a.peMetadata.exports.size();++i) {
        const auto& item=a.peMetadata.exports[i]; if(i)o<<", ";
        o<<"{\"name\": \""<<escapeJson(item.name)<<"\", \"ordinal\": "<<item.ordinal
         <<", \"rva\": \""<<hex32(item.rva)<<"\", \"forwarded\": "<<(item.forwarded?"true":"false")
         <<", \"forwarder\": \""<<escapeJson(item.forwarder)<<"\"}";
    }
    o<<"], \"certificates\": [";
    for(std::size_t i=0;i<a.peMetadata.certificates.size();++i) {
        const auto& item=a.peMetadata.certificates[i]; if(i)o<<", ";
        o<<"{\"length\": "<<item.length<<", \"revision\": "<<item.revision
         <<", \"certificate_type\": "<<item.certificateType<<", \"file_offset\": "<<item.fileOffset<<"}";
    }
    o<<"], \"base_relocations\": [";
    for(std::size_t i=0;i<a.peMetadata.relocations.size();++i) {
        const auto& item=a.peMetadata.relocations[i]; if(i)o<<", ";
        o<<"{\"page_rva\": \""<<hex32(item.pageRva)<<"\", \"target_rva\": \""<<hex32(item.targetRva)
         <<"\", \"type\": "<<unsigned(item.type)<<"}";
    }
    o<<"], \"debug_entries\": [";
    for(std::size_t i=0;i<a.peMetadata.debugEntries.size();++i) {
        const auto& item=a.peMetadata.debugEntries[i]; if(i)o<<", ";
        o<<"{\"timestamp\": "<<item.timestamp<<", \"type\": "<<item.type
         <<", \"size\": "<<item.sizeOfData<<", \"raw_pointer\": "<<item.pointerToRawData<<"}";
    }
    o<<"], \"tls\": {\"start_raw_data\": \""<<hex64(a.peMetadata.tls.startAddressOfRawData)
     <<"\", \"end_raw_data\": \""<<hex64(a.peMetadata.tls.endAddressOfRawData)
     <<"\", \"address_of_index\": \""<<hex64(a.peMetadata.tls.addressOfIndex)
     <<"\", \"zero_fill\": "<<a.peMetadata.tls.sizeOfZeroFill<<", \"callbacks\": [";
    for(std::size_t i=0;i<a.peMetadata.tls.callbackRvas.size();++i) {
        if(i)o<<", ";
        o<<"\""<<hex32(a.peMetadata.tls.callbackRvas[i])<<"\"";
    }
    o<<"]}},\n  \"imports\": [";
    for(std::size_t i=0;i<a.imports.size();++i){const auto& im=a.imports[i];if(i)o<<",";o<<"\n    {\"module\": \""<<escapeJson(im.module)<<"\", \"name\": \""<<escapeJson(im.name)<<"\", \"iat_rva\": \""<<hex32(im.iatRva)<<"\"}";}
    if(!a.imports.empty()) o<<"\n  ";
    o<<"],\n  \"delay_imports\": [";
    for(std::size_t i=0;i<a.peMetadata.delayImports.size();++i) {
        const auto& im=a.peMetadata.delayImports[i]; if(i)o<<",";
        o<<"\n    {\"module\": \""<<escapeJson(im.module)<<"\", \"name\": \""<<escapeJson(im.name)
         <<"\", \"iat_rva\": \""<<hex32(im.iatRva)<<"\", \"by_ordinal\": "<<(im.byOrdinal?"true":"false")
         <<", \"ordinal\": "<<im.ordinal<<"}";
    }
    if(!a.peMetadata.delayImports.empty()) o<<"\n  ";
    o<<"],\n  \"functions\": [";
    for(std::size_t i=0;i<a.functions.size();++i){const auto& f=a.functions[i];if(i)o<<",";o<<"\n    {\"begin_rva\": \""<<hex32(f.range.beginRva)<<"\", \"end_rva\": \""<<hex32(f.range.endRva)<<"\", \"size\": "<<(f.range.endRva-f.range.beginRva)<<", \"unwind_rva\": \""<<hex32(f.range.unwindInfoRva)<<"\", \"unwind_valid\": "<<(f.unwindValid?"true":"false")<<", \"unwind_error\": \""<<escapeJson(f.unwindError)<<"\", \"chain_valid\": "<<(f.chainValid?"true":"false")<<", \"chain_error\": \""<<escapeJson(f.chainError)<<"\", \"stack_consumed\": "<<f.unwind.stackAllocation<<", \"explicit_stack_allocation\": "<<f.unwind.explicitAllocation<<", \"frame_register\": \""<<frameRegName(f.unwind.frameRegister)<<"\", \"frame_offset_bytes\": "<<unsigned(f.unwind.frameOffset)*16<<", \"saved_registers\": [";
        for(std::size_t j=0;j<f.unwind.savedRegisters.size();++j){if(j)o<<", ";o<<"\""<<f.unwind.savedRegisters[j]<<"\"";}
        o<<"], \"saved_xmm_registers\": ["; for(std::size_t j=0;j<f.unwind.savedXmmRegisters.size();++j){if(j)o<<", ";o<<"\""<<f.unwind.savedXmmRegisters[j]<<"\"";}
        o<<"], \"chained_records\": ["; for(std::size_t j=0;j<f.chainedRecords.size();++j){if(j)o<<", ";o<<"{\"begin_rva\": \""<<hex32(f.chainedRecords[j].beginRva)<<"\", \"end_rva\": \""<<hex32(f.chainedRecords[j].endRva)<<"\", \"unwind_rva\": \""<<hex32(f.chainedRecords[j].unwindInfoRva)<<"\"}";}
        o<<"], \"calls\": ["; for(std::size_t j=0;j<f.calls.size();++j){const auto& c=f.calls[j];if(j)o<<", ";o<<"{\"instruction_rva\": \""<<hex32(c.instructionRva)<<"\", \"kind\": \""<<c.kind<<"\", \"target_rva\": \""<<hex32(c.targetRva)<<"\", \"target\": \""<<escapeJson(c.target)<<"\", \"resolved\": "<<(c.resolved?"true":"false")<<"}";}
        o<<"]}";
    }
    if(!a.functions.empty()) o<<"\n  ";
    o<<"],\n  \"call_graph\": [";
    bool first=true;
    for(const auto& f:a.functions) for(const auto& c:f.calls) {
        if(!first) o<<", ";
        first=false;
        o<<"{\"from\": \""<<hex32(f.range.beginRva)<<"\", \"to\": \""<<escapeJson(c.target)<<"\", \"kind\": \""<<c.kind<<"\", \"resolved\": "<<(c.resolved?"true":"false")<<"}";
    }
    o<<"]\n}"; return o.str();
}
}
