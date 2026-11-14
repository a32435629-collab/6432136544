#include "AIAnalyzer.hpp"

namespace lulz::ai::analysis {
AIAnalyzer::AIAnalyzer() = default;
AIAnalyzer::AIAnalyzer(const AIConfig& config) : engine_(config) {}

AnalysisResult AIAnalyzer::analyze(const AnalysisInput& input) const {
    AnalysisResult result;
    result.sourceLabel = input.sourceLabel;
    const AIAnalysisResult engineResult = engine_.analyze(input.context);
    result.success = engineResult.success;
    result.summary = engineResult.summary;
    result.findings = engineResult.findings;
    result.features = engineResult.features;
    result.neuralInferencePerformed = engineResult.neuralInferencePerformed;
    result.neuralOutput = engineResult.neuralOutput;
    result.providerConnected = engineResult.providerConnected;
    result.providerResponse = engineResult.providerResponse;
    result.error = engineResult.error;
    return result;
}
} // namespace lulz::ai::analysis
