#pragma once
#include <cstdint>
#include <span>
#include <vector>
namespace lulz {
struct FunctionCandidate { std::size_t offset{}; const char* reason{}; };
std::vector<FunctionCandidate> findX64FunctionCandidates(std::span<const std::uint8_t> bytes);
}
