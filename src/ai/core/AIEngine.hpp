
#pragma once

#include "AIConfig.hpp"
#include "AIContext.hpp"

#include <string>
#include <vector>

namespace lulz::ai {

struct AIAnalysisResult {
    bool success = false;

    std::string summary;
    std::vector<std::string> findings;

    std::string error;
};

class AIEngine {
public:
    AIEngine();
    explicit AIEngine(const AIConfig& config);

    bool setConfig(const AIConfig& config);

    const AIConfig& getConfig() const;

    AIAnalysisResult analyze(const AIContext& context) const;

    std::string version() const;
    bool isEnabled() const;

private:
    AIConfig config_;
};

} // namespace lulz::ai
