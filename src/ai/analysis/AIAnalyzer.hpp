#pragma once

#include "ai/core/AIEngine.hpp"
#include "AnalysisInput.hpp"
#include "AnalysisResult.hpp"

namespace lulz::ai::analysis {

class AIAnalyzer {
public:
    AIAnalyzer();

    explicit AIAnalyzer(const AIConfig& config);

    AnalysisResult analyze(const AnalysisInput& input) const;

private:
    AIEngine engine_;
};

} // namespace lulz::ai::analysis