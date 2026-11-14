#include "AIEngine.hpp"
#include "ai/features/FeatureExtractor.hpp"
#include "ai/neural/NeuralNetwork.hpp"
#include <fstream>
#include <sstream>

namespace lulz::ai {
namespace {
double numericFeature(const features::FeatureVector& vector, const char* name) {
    for (const auto& feature : vector.values)
        if (feature.name == name && feature.type == features::FeatureType::Numeric) return feature.value;
    return 0.0;
}
}
AIEngine::AIEngine() = default;
AIEngine::AIEngine(const AIConfig& config) : config_(config) {}
bool AIEngine::setConfig(const AIConfig& config) {
    if (!config.validate()) return false;
    config_ = config;
    return true;
}
const AIConfig& AIEngine::getConfig() const { return config_; }
bool AIEngine::isEnabled() const { return config_.enabled; }
std::string AIEngine::version() const { return "DLL_LULZ_AI Engine 0.6.0"; }

AIAnalysisResult AIEngine::analyze(const AIContext& context) const {
    AIAnalysisResult result;
    if (!config_.enabled) { result.error = "AI Engine is disabled"; return result; }
    std::string validationError;
    if (!config_.validate(&validationError)) { result.error = validationError; return result; }
    if (!context.validate(&validationError)) { result.error = validationError; return result; }
    if (context.functions.size() > config_.maxFunctions) { result.error = "Function limit exceeded"; return result; }
    if (context.imports.size() > config_.maxImports) { result.error = "Import limit exceeded"; return result; }
    const auto instructions = context.instructionCount();
    if (instructions > config_.maxInstructions) { result.error = "Instruction limit exceeded"; return result; }

    result.features = features::FeatureExtractor{}.extract(context);
    if (config_.provider == AIProvider::Local) {
        std::ifstream modelFile(config_.modelPath, std::ios::binary);
        if (!modelFile) {
            result.neuralError = "Cannot open local model checkpoint: " + config_.modelPath;
        } else {
            std::string loadError;
            auto model = neural::NeuralNetwork::load(modelFile, &loadError);
            if (!model) {
                result.neuralError = "Cannot load local model: " + loadError;
            } else {
                std::vector<double> input;
                for (const auto& feature : result.features.values)
                    if (feature.type == features::FeatureType::Numeric) input.push_back(feature.value);
                std::string predictError;
                auto prediction = model->predict(input, &predictError);
                if (!prediction) result.neuralError = "Neural inference failed: " + predictError;
                else {
                    result.neuralInferencePerformed = true;
                    result.neuralOutput = std::move(*prediction);
                }
            }
        }
    } else if (config_.provider == AIProvider::OpenAI) {
        result.neuralError = "OpenAI transport is not configured in this build; use a local .lznn checkpoint";
    }

    std::ostringstream report;
    report << "DLL_LULZ_AI Analysis Report\n==========================\n\n";
    report << "File: " << context.filePath << '\n'
           << "Format: " << context.format << '\n'
           << "Architecture: " << context.architecture << '\n';
    report << "\nStatistics:\nFunctions: " << context.functions.size()
           << "\nImports: " << context.imports.size()
           << "\nDecoded instructions: " << instructions
           << "\nExtracted features: " << result.features.size() << '\n';
    report << "\nAI Provider: ";
    switch (config_.provider) {
        case AIProvider::None: report << "None (static analysis only)"; break;
        case AIProvider::Local: report << "Local checkpoint"; break;
        case AIProvider::OpenAI: report << "OpenAI (not configured)"; break;
    }
    report << '\n';
    if (!config_.modelName.empty()) report << "Model: " << config_.modelName << '\n';
    report << "Neural inference: " << (result.neuralInferencePerformed ? "performed" : "not performed") << '\n';
    if (!result.neuralError.empty()) report << "Neural status: " << result.neuralError << '\n';
    if (result.neuralInferencePerformed) {
        report << "Neural output:";
        for (double value : result.neuralOutput) report << ' ' << value;
        report << '\n';
    }
    result.summary = report.str();

    result.findings.push_back("Static metadata, decoded instructions and feature extraction completed.");
    if (instructions == 0) result.findings.push_back("No machine instructions were decoded for the supplied functions.");
    if (numericFeature(result.features, "imports.dynamic_resolution") > 0.0)
        result.findings.push_back("Dynamic API resolution indicators were found in the import names.");
    if (numericFeature(result.features, "imports.remote_memory") > 0.0)
        result.findings.push_back("Remote-process memory API indicators were found; inspect call sites and context.");
    if (numericFeature(result.features, "imports.persistence") > 0.0)
        result.findings.push_back("Persistence-related API indicators were found in the import names.");
    if (numericFeature(result.features, "imports.anti_analysis") > 0.0)
        result.findings.push_back("Anti-analysis or debugger-query API indicators were found.");
    if (numericFeature(result.features, "instructions.control_flow") > 0.0)
        result.findings.push_back("Decoded control-flow instruction indicators were included in the feature vector.");
    if (result.neuralInferencePerformed)
        result.findings.push_back("A supplied neural checkpoint produced an inference output; interpret it using that model's documented labels and validation.");
    else if (config_.provider == AIProvider::Local)
        result.findings.push_back("Local neural inference was skipped because the configured checkpoint could not be loaded or did not match the feature vector.");
    if (!context.additionalNotes.empty()) result.findings.push_back("Additional analysis notes are available.");
    result.findings.push_back("Static heuristics are not a malware verdict; inference quality depends on the supplied model and its training data.");
    result.success = true;
    return result;
}
} // namespace lulz::ai
