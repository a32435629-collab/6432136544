
#include "AIEngine.hpp"

#include <sstream>

namespace lulz::ai {

AIEngine::AIEngine() = default;

AIEngine::AIEngine(const AIConfig& config)
    : config_(config) {
}

bool AIEngine::setConfig(const AIConfig& config) {
    if (!config.validate()) {
        return false;
    }

    config_ = config;
    return true;
}

const AIConfig& AIEngine::getConfig() const {
    return config_;
}

bool AIEngine::isEnabled() const {
    return config_.enabled;
}

std::string AIEngine::version() const {
    return "DLL_LULZ_AI Engine 0.1.0";
}

AIAnalysisResult AIEngine::analyze(
    const AIContext& context
) const {
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

    std::ostringstream report;

    report << "DLL_LULZ_AI Analysis Report\n";
    report << "==========================\n\n";

    report << "File: " << context.filePath << '\n';
    report << "Format: " << context.format << '\n';
    report << "Architecture: " << context.architecture << '\n';

    report << "\nStatistics:\n";
    report << "Functions: " << context.functions.size() << '\n';
    report << "Imports: " << context.imports.size() << '\n';
    report << "Instructions: " << instructions << '\n';

    report << "\nAI Provider: ";

    switch (config_.provider) {
        case AIProvider::None:
            report << "Not connected";
            break;

        case AIProvider::Local:
            report << "Local";
            break;

        case AIProvider::OpenAI:
            report << "OpenAI";
            break;
    }

    report << '\n';

    if (!config_.modelName.empty()) {
        report << "Model: " << config_.modelName << '\n';
    }

    result.summary = report.str();

    result.findings.push_back(
        "Binary metadata was accepted successfully."
    );

    result.findings.push_back(
        "Function and instruction counts were collected."
    );

    result.findings.push_back(
        "No neural model inference has been performed yet."
    );

    if (!context.additionalNotes.empty()) {
        result.findings.push_back(
            "Additional analysis notes are available."
        );
    }

    result.success = true;
    return result;
}

} // namespace lulz::ai
