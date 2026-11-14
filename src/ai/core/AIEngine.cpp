#include "AIEngine.hpp"

#include "ai/features/FeatureExtractor.hpp"

#include <sstream>

namespace lulz::ai {
namespace {
double numericFeature(const features::FeatureVector& vector, const char* name) {
    for (const auto& feature : vector.values) {
        if (feature.name == name && feature.type == features::FeatureType::Numeric)
            return feature.value;
    }
    return 0.0;
}
} // namespace

AIEngine::AIEngine() = default;
AIEngine::AIEngine(const AIConfig& config) : config_(config) {}

bool AIEngine::setConfig(const AIConfig& config) {
    if (!config.validate()) return false;
    config_ = config;
    return true;
}
const AIConfig& AIEngine::getConfig() const { return config_; }
bool AIEngine::isEnabled() const { return config_.enabled; }
std::string AIEngine::version() const { return "DLL_LULZ_AI Engine 0.2.0"; }

AIAnalysisResult AIEngine::analyze(const AIContext& context) const {
    AIAnalysisResult result;
    if (!config_.enabled) {
        result.error = "AI Engine is disabled";
        return result;
    }

    std::string validationError;
    if (!config_.validate(&validationError)) {
        result.error = validationError;
        return result;
    }
    if (!context.validate(&validationError)) {
        result.error = validationError;
        return result;
    }
    if (context.functions.size() > config_.maxFunctions) {
        result.error = "Function limit exceeded";
        return result;
    }
    if (context.imports.size() > config_.maxImports) {
        result.error = "Import limit exceeded";
        return result;
    }
    const auto instructions = context.instructionCount();
    if (instructions > config_.maxInstructions) {
        result.error = "Instruction limit exceeded";
        return result;
    }

    result.features = features::FeatureExtractor{}.extract(context);

    std::ostringstream report;
    report << "DLL_LULZ_AI Analysis Report\n";
    report << "==========================\n\n";
    report << "File: " << context.filePath << '\n';
    report << "Format: " << context.format << '\n';
    report << "Architecture: " << context.architecture << '\n';
    report << "\nStatistics:\n";
    report << "Functions: " << context.functions.size() << '\n';
    report << "Imports: " << context.imports.size() << '\n';
    report << "Decoded instructions: " << instructions << '\n';
    report << "Extracted features: " << result.features.size() << '\n';
    report << "\nAI Provider: ";
    switch (config_.provider) {
        case AIProvider::None: report << "Not connected"; break;
        case AIProvider::Local: report << "Local"; break;
        case AIProvider::OpenAI: report << "OpenAI"; break;
    }
    report << '\n';
    if (!config_.modelName.empty()) report << "Model: " << config_.modelName << '\n';
    result.summary = report.str();

    result.findings.push_back("Static metadata and feature extraction completed.");
    if (instructions == 0) {
        result.findings.push_back("Instruction-level evidence is unavailable; no decoded instruction text was supplied.");
    }
    if (numericFeature(result.features, "imports.dynamic_resolution") > 0.0) {
        result.findings.push_back("Dynamic API resolution indicators were found in the import names.");
    }
    if (numericFeature(result.features, "imports.remote_memory") > 0.0) {
        result.findings.push_back("Remote-process memory API indicators were found; inspect call sites and context.");
    }
    if (numericFeature(result.features, "imports.persistence") > 0.0) {
        result.findings.push_back("Persistence-related API indicators were found in the import names.");
    }
    if (numericFeature(result.features, "imports.anti_analysis") > 0.0) {
        result.findings.push_back("Anti-analysis or debugger-query API indicators were found.");
    }
    if (numericFeature(result.features, "instructions.control_flow") > 0.0) {
        result.findings.push_back("Decoded control-flow instruction indicators were included in the feature vector.");
    }
    if (!context.additionalNotes.empty()) {
        result.findings.push_back("Additional analysis notes are available.");
    }
    result.findings.push_back("These are static heuristics, not a malware verdict; no trained-model inference was performed.");

    result.success = true;
    return result;
}
} // namespace lulz::ai
