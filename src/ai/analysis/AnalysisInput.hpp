#pragma once

#include "ai/core/AIContext.hpp"

#include <string>

namespace lulz::ai::analysis {

struct AnalysisInput {
    AIContext context;
    std::string sourceLabel = "DLL_LULZ_AI";
};

} // namespace lulz::ai::analysis