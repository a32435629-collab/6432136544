#include "lulz/analysis/InstructionIR.hpp"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <sstream>
namespace lulz {
namespace {
InstructionKind classify(const char* category, const char* mnemonic) {
    const std::string c = category ? category : "";
    const std::string m = mnemonic ? mnemonic : "";
    if (m == "call") return InstructionKind::Call;
    if (m == "ret" || m == "retf" || m == "iret" || m == "iretd" || m == "iretq") return InstructionKind::Return;
    if (c == "BRANCH" || c == "COND_BR" || c == "UNCOND_BR" || c == "INTERRUPT") return InstructionKind::Branch;
    if (c == "PUSH" || c == "POP") return InstructionKind::Stack;
    if (c == "DATAXFER" || c == "CMOV" || c == "SETCC") return InstructionKind::DataMovement;
    if (c == "BINARY" || c == "DECIMAL" || c == "SHIFT" || c == "ROTATE") return InstructionKind::Arithmetic;
    if (c == "LOGICAL") return InstructionKind::Logic;
    if (c == "COMPARE") return InstructionKind::Compare;
    if (c == "STRINGOP") return InstructionKind::String;
    if (c == "SYSTEM" || c == "SYSCALL" || c == "SYSRET" || c == "VTX" || c == "SGX") return InstructionKind::System;
    if (c == "FPU") return InstructionKind::FloatingPoint;
    if (c == "AVX" || c == "AVX2" || c == "AVX2GATHER" || c == "AVX512" || c == "SSE") return InstructionKind::Vector;
    return InstructionKind::Other;
}
std::string operandAccess(ZydisOperandActions actions) {
    const bool read = (actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
    const bool write = (actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
    if (read && write) return "read_write";
    if (write) return "write";
    if (read) return "read";
    return "none";
}
IROperand convertOperand(const ZydisDecodedOperand& source) {
    IROperand out;
    out.bitWidth = source.size;
    out.access = operandAccess(source.actions);
    switch (source.type) {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        out.kind = "register"; out.registerName = ZydisRegisterGetString(source.reg.value); break;
    case ZYDIS_OPERAND_TYPE_MEMORY:
        out.kind = "memory";
        if (source.mem.base != ZYDIS_REGISTER_NONE) out.baseRegister = ZydisRegisterGetString(source.mem.base);
        if (source.mem.index != ZYDIS_REGISTER_NONE) out.indexRegister = ZydisRegisterGetString(source.mem.index);
        out.scale = source.mem.scale ? source.mem.scale : 1;
        out.hasDisplacement = source.mem.disp.has_displacement;
        out.displacement = source.mem.disp.value;
        break;
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        out.kind = "immediate"; out.immediate = source.imm.value.u; out.relative = source.imm.is_relative; break;
    case ZYDIS_OPERAND_TYPE_POINTER:
        out.kind = "pointer"; out.immediate = source.ptr.offset; break;
    default: out.kind = "other"; break;
    }
    return out;
}
}
const char* instructionKindName(InstructionKind kind) noexcept {
    switch (kind) {
    case InstructionKind::Other: return "other"; case InstructionKind::DataMovement: return "data_movement";
    case InstructionKind::Arithmetic: return "arithmetic"; case InstructionKind::Logic: return "logic";
    case InstructionKind::Compare: return "compare"; case InstructionKind::Branch: return "branch";
    case InstructionKind::Call: return "call"; case InstructionKind::Return: return "return";
    case InstructionKind::Stack: return "stack"; case InstructionKind::String: return "string";
    case InstructionKind::System: return "system"; case InstructionKind::FloatingPoint: return "floating_point";
    case InstructionKind::Vector: return "vector"; case InstructionKind::Unknown: return "unknown";
    }
    return "unknown";
}
InstructionDecodeResult decodeInstructionIR(std::span<const std::uint8_t> bytes, std::uint64_t baseAddress, X86Mode mode) {
    InstructionDecodeResult result; result.mode = mode;
    ZydisDecoder decoder{};
    const auto machineMode = mode == X86Mode::X86_64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    const auto stackWidth = mode == X86Mode::X86_64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machineMode, stackWidth))) {
        result.diagnostics.push_back({baseAddress, "Zydis decoder initialization failed"});
        result.undecodableBytes = bytes.size(); return result;
    }
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        ZydisDecodedInstruction decoded{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        const auto status = ZydisDecoderDecodeFull(&decoder, bytes.data() + cursor, bytes.size() - cursor, &decoded, operands);
        if (!ZYAN_SUCCESS(status) || decoded.length == 0) {
            std::ostringstream message; message << "Undecodable byte 0x" << std::hex << static_cast<unsigned>(bytes[cursor]);
            result.diagnostics.push_back({baseAddress + cursor, message.str()});
            InstructionIR data; data.address = baseAddress + cursor; data.length = 1; data.mnemonic = "db";
            data.category = "DATA"; data.kind = InstructionKind::Unknown;
            data.classification = ByteClassification::UndecodableData; data.valid = false;
            result.instructions.push_back(std::move(data)); ++result.undecodableBytes; ++cursor; continue;
        }
        InstructionIR ir; ir.address = baseAddress + cursor; ir.length = decoded.length;
        ir.mnemonic = ZydisMnemonicGetString(decoded.mnemonic);
        ir.category = ZydisCategoryGetString(decoded.meta.category);
        ir.kind = classify(ir.category.c_str(), ir.mnemonic.c_str());
        ir.valid = true; ir.classification = ByteClassification::Instruction;
        const auto visible = std::min<std::size_t>(decoded.operand_count_visible, ZYDIS_MAX_OPERAND_COUNT);
        ir.operands.reserve(visible);
        for (std::size_t i = 0; i < visible; ++i) ir.operands.push_back(convertOperand(operands[i]));
        result.instructions.push_back(std::move(ir)); cursor += decoded.length; result.decodedBytes += decoded.length;
    }
    return result;
}
} // namespace lulz
