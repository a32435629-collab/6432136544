
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lulz::ai {

struct FunctionInfo {
    std::string name;
    std::uint64_t address = 0;
    std::vector<std::string> assembly;
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
