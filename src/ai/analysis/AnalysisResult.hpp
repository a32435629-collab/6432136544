#pragma once

#include "ai/features/FeatureVector.hpp"

#include <string>
#include <vector>

namespace lulz::ai::analysis {
struct AnalysisResult {
    bool success = false;
    std::string sourceLabel;
    std::string summary;
    std::vector<std::string> findings;
    features::FeatureVector features;
    std::string error;
};
} // namespace lulz::ai::analysis
