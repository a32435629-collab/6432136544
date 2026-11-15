#include "AIEngine.hpp"
#include "ai/features/FeatureExtractor.hpp"
#include "ai/neural/NeuralNetwork.hpp"
#include "ai/providers/OpenAIClient.hpp"
#include "ai/providers/DeepSeekClient.hpp"
#include <cstdlib>
#include <cmath>
#include <fstream>
#include <sstream>
#include <utility>

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
std::string AIEngine::version() const { return "DLL_LULZ_AI Engine 0.7.0"; }

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
                std::vector<std::string> featureNames;
                for (const auto& feature : result.features.values) {
                    if (feature.type == features::FeatureType::Numeric) {
                        input.push_back(feature.value);
                        featureNames.push_back(feature.name);
                    }
                }

                // Trainer-generated checkpoints carry a sibling .norm file. Apply
                // exactly the training-set normalization before local inference.
                std::ifstream normalizerFile(config_.modelPath + ".norm");
                if (normalizerFile) {
                    std::string magic;
                    std::string countLine;
                    std::getline(normalizerFile, magic);
                    std::getline(normalizerFile, countLine);
                    std::size_t count = 0;
                    try { count = static_cast<std::size_t>(std::stoul(countLine)); }
                    catch (...) { count = 0; }
                    if (magic != "LULZNORM1" || count != input.size()) {
                        result.neuralError = "Invalid or incompatible model normalization metadata";
                    } else {
                        for (std::size_t i = 0; i < count; ++i) {
                            std::string line;
                            if (!std::getline(normalizerFile, line)) {
                                result.neuralError = "Truncated model normalization metadata";
                                break;
                            }
                            const auto first = line.find(',');
                            const auto second = first == std::string::npos ? first : line.find(',', first + 1);
                            if (first == std::string::npos || second == std::string::npos ||
                                line.substr(0, first) != featureNames[i]) {
                                result.neuralError = "Model feature schema does not match current extractor";
                                break;
                            }
                            try {
                                const double mean = std::stod(line.substr(first + 1, second - first - 1));
                                const double scale = std::stod(line.substr(second + 1));
                                if (!std::isfinite(mean) || !std::isfinite(scale) || scale <= 0.0) {
                                    result.neuralError = "Invalid normalization parameters";
                                    break;
                                }
                                input[i] = (input[i] - mean) / scale;
                            } catch (...) {
                                result.neuralError = "Invalid normalization parameters";
                                break;
                            }
                        }
                    }
                }

                if (result.neuralError.empty()) {
                    std::string predictError;
                    auto prediction = model->predict(input, &predictError);
                    if (!prediction) result.neuralError = "Neural inference failed: " + predictError;
                    else {
                        result.neuralInferencePerformed = true;
                        result.neuralOutput = std::move(*prediction);
                    }
                }
            }
        }
    } else if (config_.provider == AIProvider::OpenAI ||
               config_.provider == AIProvider::DeepSeek ||
               config_.provider == AIProvider::Groq) {
        const bool useDeepSeek = config_.provider == AIProvider::DeepSeek;
        const bool useGroq = config_.provider == AIProvider::Groq;
        const char* key = std::getenv(useDeepSeek ? "DEEPSEEK_API_KEY" :
                                      (useGroq ? "GROQ_API_KEY" : "OPENAI_API_KEY"));
        std::ostringstream prompt;
        prompt << "Review these static PE analysis features. Explain noteworthy indicators, limitations, and benign alternatives. Do not issue a definitive malware verdict.\n";
        for (const auto& feature : result.features.values) {
            prompt << feature.name << " = ";
            if (feature.type == features::FeatureType::Categorical) prompt << feature.textValue;
            else prompt << feature.value;
            prompt << '\n';
        }
        const std::string endpoint = config_.endpoint.empty()
            ? (useDeepSeek ? "https://api.deepseek.com/chat/completions" :
               (useGroq ? "https://api.groq.com/openai/v1/chat/completions"
                        : "https://api.openai.com/v1/chat/completions"))
            : config_.endpoint;
        const std::string model = config_.modelName.empty()
            ? (useDeepSeek ? "deepseek-flash" :
               (useGroq ? "openai/gpt-oss-20b" : "gpt-4o-mini"))
            : config_.modelName;
        std::string response;
        std::string providerError;
        const bool connected = useDeepSeek
            ? providers::analyzeWithDeepSeek(endpoint, key ? key : "",
                  model, prompt.str(), response, &providerError)
            : providers::analyzeWithOpenAI(endpoint, key ? key : "",
                  model, prompt.str(), response, &providerError);
        if (connected) {
            result.providerConnected = true;
            result.providerResponse = std::move(response);
        } else {
            result.neuralError = providerError;
        }
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
        case AIProvider::OpenAI: report << (result.providerConnected ? "OpenAI (connected)" : "OpenAI (not connected)"); break;
        case AIProvider::DeepSeek: report << (result.providerConnected ? "DeepSeek (connected)" : "DeepSeek (not connected)"); break;
        case AIProvider::Groq: report << (result.providerConnected ? "Groq (connected)" : "Groq (not connected)"); break;
    }
    report << '\n';
    if (!config_.modelName.empty()) report << "Model: " << config_.modelName << '\n';
    report << "Neural inference: " << (result.neuralInferencePerformed ? "performed" : "not performed") << '\n';
    if (!result.neuralError.empty()) report << "Provider/model status: " << result.neuralError << '\n';
    if (result.providerConnected) report << "Provider response: " << result.providerResponse << '\n';
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
    if (result.providerConnected) result.findings.push_back(
        (config_.provider == AIProvider::DeepSeek ? "DeepSeek" :
         (config_.provider == AIProvider::Groq ? "Groq" : "OpenAI")) +
        std::string(" provider returned an interpretation of the extracted static features."));
    if (result.neuralInferencePerformed)
        result.findings.push_back("A supplied neural checkpoint produced an inference output; interpret it using the model documentation and validation.");
    else if (config_.provider == AIProvider::Local)
        result.findings.push_back("Local neural inference was skipped because the configured checkpoint could not be loaded or did not match the feature vector.");
    if (!context.additionalNotes.empty()) result.findings.push_back("Additional analysis notes are available.");
    result.findings.push_back("Static heuristics are not a malware verdict; inference quality depends on the supplied model and its training data.");
    result.success = true;
    return result;
}
} // namespace lulz::ai
