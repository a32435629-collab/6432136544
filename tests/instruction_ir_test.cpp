#include "lulz/analysis/InstructionIR.hpp"
#include <cassert>
#include <cstdint>
#include <vector>
int main() {
    using namespace lulz;
    const std::vector<std::uint8_t> x64{0x48,0x89,0xd8,0x48,0x83,0xc0,0x01,0xe8,0,0,0,0,0xc3};
    const auto decoded = decodeInstructionIR(x64, 0x1000, X86Mode::X86_64);
    assert(decoded.instructions.size() == 4 && decoded.decodedBytes == x64.size() && decoded.undecodableBytes == 0);
    assert(decoded.instructions[0].mnemonic == "mov" && decoded.instructions[0].kind == InstructionKind::DataMovement);
    assert(decoded.instructions[0].operands.size() == 2 && decoded.instructions[0].operands[0].registerName == "rax");
    assert(decoded.instructions[0].operands[1].registerName == "rbx");
    assert(decoded.instructions[1].kind == InstructionKind::Arithmetic && decoded.instructions[1].operands[1].kind == "immediate");
    assert(decoded.instructions[2].kind == InstructionKind::Call && decoded.instructions[3].kind == InstructionKind::Return);
    assert(decoded.instructions[0].address == 0x1000 && decoded.instructions[3].address == 0x100c);
    const std::vector<std::uint8_t> x86{0x89,0xd8,0xc3};
    const auto decoded32 = decodeInstructionIR(x86, 0x2000, X86Mode::X86_32);
    assert(decoded32.instructions.size() == 2 && decoded32.instructions[0].mnemonic == "mov");
    assert(decoded32.instructions[1].kind == InstructionKind::Return);
    const std::vector<std::uint8_t> damaged{0x90,0x0f};
    const auto damagedResult = decodeInstructionIR(damaged, 0x3000);
    assert(damagedResult.instructions.size() == 2 && damagedResult.instructions[0].valid && !damagedResult.instructions[1].valid);
    assert(damagedResult.instructions[1].classification == ByteClassification::UndecodableData);
    assert(damagedResult.undecodableBytes == 1 && damagedResult.diagnostics.size() == 1 && damagedResult.diagnostics[0].address == 0x3001);
    return 0;
}
