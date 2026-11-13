
#pragma once

#include <cstddef>
#include <string>

namespace lulz::ai {

enum class AIProvider {
    None,
    Local,
    OpenAI
};

struct AIConfig {
    bool enabled = true;

    AIProvider provider = AIProvider::None;

    std::string modelName = "none";
    std::string endpoint;

    std::size_t maxFunctions = 1000;
    std::size_t maxImports = 5000;
    std::size_t maxInstructions = 50000;

    bool validate(std::string* error = nullptr) const;
};

} // namespace lulz::ai
