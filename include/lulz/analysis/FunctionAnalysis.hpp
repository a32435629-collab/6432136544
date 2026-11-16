#pragma once
#include "lulz/core/Result.hpp"
#include "lulz/formats/pe/PEParser.hpp"
#include "lulz/formats/pe/PEExtendedParser.hpp"
#include "lulz/formats/pe/UnwindInfo.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz {
struct DecodedInstruction {
    std::uint32_t rva{};
    std::uint8_t length{};
    std::string mnemonic;
};
struct FunctionCall {
    std::uint32_t instructionRva{};
    std::uint32_t targetRva{};
    std::string kind;
    std::string target;
    bool resolved{};
};
struct AnalyzedFunction {
    RuntimeFunctionEntry range;
    UnwindInfo unwind;
    std::vector<RuntimeFunctionEntry> chainedRecords;
    std::vector<DecodedInstruction> instructions;
    std::vector<FunctionCall> calls;
};
struct HeuristicFunctionCandidate {
    std::uint32_t beginRva{};
    std::string reason;
};
struct FunctionAnalysis {
    std::string entryPointSection;
    std::vector<std::uint8_t> entryPointBytes;
    std::vector<std::string> entryPointInstructions;
    std::vector<HeuristicFunctionCandidate> heuristicCandidates;
    PEExtendedInfo peMetadata;
    std::vector<AnalyzedFunction> functions;
    std::vector<ImportSymbol> imports;
    std::size_t unresolvedCalls{};
    std::size_t decodedInstructions{};
    std::size_t undecodableBytes{};
    std::vector<std::string> warnings;
};
Result<FunctionAnalysis> analyzePEFunctions(std::span<const std::uint8_t> bytes, const PEInfo& pe);
std::string functionAnalysisToJson(const FunctionAnalysis& analysis, const PEInfo& pe);
}
