#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace lulz {
enum class X86Mode { X86_32, X86_64 };
enum class InstructionKind { Other, DataMovement, Arithmetic, Logic, Compare, Branch, Call, Return, Stack, String, System, FloatingPoint, Vector, Unknown };
enum class ByteClassification { Instruction, UndecodableData };
struct IROperand {
    std::string kind, access, registerName, baseRegister, indexRegister;
    std::int64_t displacement{};
    std::uint64_t immediate{};
    std::uint32_t bitWidth{};
    std::uint8_t scale{1};
    bool relative{}, hasDisplacement{};
};
struct InstructionIR {
    std::uint64_t address{};
    std::uint8_t length{};
    std::string mnemonic, category;
    InstructionKind kind{InstructionKind::Unknown};
    std::vector<IROperand> operands;
    ByteClassification classification{ByteClassification::Instruction};
    bool valid{};
};
struct DecodeDiagnostic { std::uint64_t address{}; std::string message; };
struct InstructionDecodeResult {
    X86Mode mode{X86Mode::X86_64};
    std::vector<InstructionIR> instructions;
    std::vector<DecodeDiagnostic> diagnostics;
    std::size_t decodedBytes{}, undecodableBytes{};
};
InstructionDecodeResult decodeInstructionIR(std::span<const std::uint8_t> bytes, std::uint64_t baseAddress = 0, X86Mode mode = X86Mode::X86_64);
const char* instructionKindName(InstructionKind kind) noexcept;
} // namespace lulz
