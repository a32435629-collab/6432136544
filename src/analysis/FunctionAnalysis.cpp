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
    auto runtime=parsePEExceptionDirectory(bytes,pe);
    if(!runtime) return Result<FunctionAnalysis>::failure(".pdata: "+runtime.error());
    auto imports=parsePEImports(bytes,pe);
    if(!imports) return Result<FunctionAnalysis>::failure("imports: "+imports.error());
    FunctionAnalysis result; result.imports=std::move(imports.value());
    result.functions.reserve(runtime.value().size());
    for(const auto& fn:runtime.value()) {
        auto unwind=parsePEUnwindInfo(bytes,pe,fn);
        if(!unwind) return Result<FunctionAnalysis>::failure("UNWIND_INFO at "+hex32(fn.unwindInfoRva)+": "+unwind.error());
        AnalyzedFunction af; af.range=fn; af.unwind=std::move(unwind.value());
        // Follow chained RUNTIME_FUNCTION records with cycle and depth protection.
        std::set<std::uint32_t> seen{fn.unwindInfoRva};
        auto chain=af.unwind;
        for(unsigned depth=0;chain.chained && depth<32;++depth) {
            const auto next=chain.chainedFunction;
            if(!seen.insert(next.unwindInfoRva).second) return Result<FunctionAnalysis>::failure("cyclic CHAININFO reference at "+hex32(next.unwindInfoRva));
            af.chainedRecords.push_back(next);
            auto nested=parsePEUnwindInfo(bytes,pe,next);
            if(!nested) return Result<FunctionAnalysis>::failure("chained UNWIND_INFO at "+hex32(next.unwindInfoRva)+": "+nested.error());
            chain=std::move(nested.value());
        }
        if(chain.chained) return Result<FunctionAnalysis>::failure("CHAININFO nesting exceeds 32 levels");
        result.functions.push_back(std::move(af));
    }
    std::sort(result.functions.begin(),result.functions.end(),[](const auto& a,const auto& b){return a.range.beginRva<b.range.beginRva;});
    std::map<std::uint32_t,std::string> iat;
    for(const auto& im:result.imports) iat[im.iatRva]=im.module+"!"+im.name;

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
                ++cursor;
                continue;
            }

            const auto mnemonic = instruction.mnemonic;
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
                            call.target = "IAT[" + hex32(call.targetRva) + "]";
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
    std::ostringstream o; o<<"{\n  \"format\": \"PE32+ x64\",\n  \"image_base\": \""<<hex64(pe.imageBase)<<"\",\n  \"function_count\": "<<a.functions.size()<<",\n  \"unresolved_calls\": "<<a.unresolvedCalls<<",\n  \"function_boundary_source\": \"PE exception directory (.pdata)\",\n  \"call_scan_mode\": \"Zydis x64 instruction decoding\",\n  \"analysis_limits\": [\"Call sites are decoded instruction boundaries; indirect targets other than RIP-relative IAT slots may remain unresolved.\", \"Indirect calls are resolved only for RIP-relative IAT forms FF 15/FF 25.\"],\n  \"imports\": [";
    for(std::size_t i=0;i<a.imports.size();++i){const auto& im=a.imports[i];if(i)o<<",";o<<"\n    {\"module\": \""<<escapeJson(im.module)<<"\", \"name\": \""<<escapeJson(im.name)<<"\", \"iat_rva\": \""<<hex32(im.iatRva)<<"\"}";}
    if(!a.imports.empty()) o<<"\n  ";
    o<<"],\n  \"functions\": [";
    for(std::size_t i=0;i<a.functions.size();++i){const auto& f=a.functions[i];if(i)o<<",";o<<"\n    {\"begin_rva\": \""<<hex32(f.range.beginRva)<<"\", \"end_rva\": \""<<hex32(f.range.endRva)<<"\", \"size\": "<<(f.range.endRva-f.range.beginRva)<<", \"unwind_rva\": \""<<hex32(f.range.unwindInfoRva)<<"\", \"stack_consumed\": "<<f.unwind.stackAllocation<<", \"explicit_stack_allocation\": "<<f.unwind.explicitAllocation<<", \"frame_register\": \""<<frameRegName(f.unwind.frameRegister)<<"\", \"frame_offset_bytes\": "<<unsigned(f.unwind.frameOffset)*16<<", \"saved_registers\": [";
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
