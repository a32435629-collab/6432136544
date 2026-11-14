#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lulz::ai {
struct FunctionInfo {
    std::string name;
    std::uint64_t address = 0;
    bool hasDecodedInstructions = false;
    // Human-readable assembly lines retained for compatibility and reports.
    std::vector<std::string> assembly;
    // Mnemonics emitted by the real machine-code decoder.
    std::vector<std::string> decodedInstructions;
};
struct AIContext {
    std::string filePath;
    std::string format = "PE";
    std::string architecture = "x64";
    std::vector<std::string> imports;
    std::vector<FunctionInfo> functions;
    std::string additionalNotes;
    bool validate(std::string* error = nullptr) const;
    std::size_t instructionCount() const;
};
} // namespace lulz::ai
