#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace lulz {
struct Instruction { std::size_t offset{}; std::size_t size{}; std::string text; bool valid{}; };
std::vector<Instruction> disassembleX86Subset(std::span<const std::uint8_t> bytes, std::uint64_t base = 0);
}
