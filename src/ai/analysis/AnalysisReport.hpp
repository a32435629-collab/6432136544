#pragma once

#include "AnalysisResult.hpp"

#include <string>

namespace lulz::ai::analysis {

class AnalysisReport {
public:
    static std::string toText(const AnalysisResult& result);
};

} // namespace lulz::ai::analysis