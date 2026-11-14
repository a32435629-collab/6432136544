#include "ai/core/AIEngine.hpp"
#include "ai/analysis/AIAnalyzer.hpp"
#include "ai/analysis/AnalysisReport.hpp"
#include "ai/features/FeatureExtractor.hpp"
#include "ai/neural/NeuralNetwork.hpp"

#include <algorithm>
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>

namespace {
double valueOf(const lulz::ai::features::FeatureVector& vector, const std::string& name) {
    for (const auto& feature : vector.values)
        if (feature.name == name) return feature.value;
    assert(false && "feature not found");
    return 0.0;
}
}

int main() {
    using namespace lulz::ai;
    AIContext context;
    context.filePath = "sample.exe";
    context.imports = {
        "KERNEL32.DLL!LoadLibraryA",
        "KERNEL32.DLL!VirtualAllocEx",
        "KERNEL32.DLL!WriteProcessMemory",
        "ADVAPI32.DLL!RegSetValueExW",
        "KERNEL32.DLL!IsDebuggerPresent"
    };
    FunctionInfo decoded;
    decoded.name = "entry";
    decoded.hasDecodedInstructions = true;
    decoded.assembly = {"mov rax, rbx", "call rax", "jne 0x10", "ret", "sub rsp, 0x20"};
    context.functions.push_back(decoded);
    FunctionInfo undecoded;
    undecoded.name = "unknown";
    context.functions.push_back(undecoded);

    const auto vector = features::FeatureExtractor{}.extract(context);
    assert(valueOf(vector, "imports.dynamic_resolution") == 1.0);
    assert(valueOf(vector, "imports.remote_memory") == 2.0);
    assert(valueOf(vector, "imports.persistence") == 1.0);
    assert(valueOf(vector, "imports.anti_analysis") == 1.0);
    assert(valueOf(vector, "functions.decoded") == 1.0);
    assert(valueOf(vector, "functions.undecoded") == 1.0);
    assert(valueOf(vector, "instructions.calls") == 1.0);
    assert(valueOf(vector, "instructions.jumps") == 1.0);
    assert(valueOf(vector, "instructions.returns") == 1.0);
    assert(valueOf(vector, "instructions.stack_operations") == 1.0);

    AIEngine engine;
    const auto result = engine.analyze(context);
    assert(result.success);
    assert(!result.features.empty());
    assert(result.summary.find("Extracted features:") != std::string::npos);
    assert(!result.findings.empty());

    analysis::AnalysisInput input;
    input.context = context;
    const auto analyzed = analysis::AIAnalyzer{}.analyze(input);
    assert(analyzed.success);
    assert(analyzed.sourceLabel == input.sourceLabel);
    assert(!analyzed.features.empty());
    const auto report = analysis::AnalysisReport::toText(analyzed);
    assert(report.find("imports.remote_memory") != std::string::npos);

    AIConfig limited;
    limited.maxFunctions = 1;
    AIEngine limitedEngine(limited);
    const auto rejected = limitedEngine.analyze(context);
    assert(!rejected.success);
    assert(rejected.error == "Function limit exceeded");


    const auto numericCount = static_cast<std::size_t>(std::count_if(
        vector.values.begin(), vector.values.end(),
        [](const auto& feature) { return feature.type == features::FeatureType::Numeric; }));
    neural::NeuralNetwork checkpoint({numericCount, 4, 1});
    assert(checkpoint.valid());
    const auto modelPath = std::filesystem::temp_directory_path() / "lulz_ai_test_model.lznn";
    {
        std::ofstream modelFile(modelPath, std::ios::binary);
        assert(modelFile && checkpoint.save(modelFile));
    }
    AIConfig localConfig;
    localConfig.provider = AIProvider::Local;
    localConfig.modelName = "test-checkpoint";
    localConfig.modelPath = modelPath.string();
    const auto localResult = AIEngine(localConfig).analyze(context);
    assert(localResult.success);
    assert(localResult.neuralInferencePerformed);
    assert(localResult.neuralOutput.size() == 1);
    std::filesystem::remove(modelPath);

    AIContext decodedContext;
    decodedContext.filePath = "decoded.exe";
    FunctionInfo realDecoded;
    realDecoded.name = "decoded";
    realDecoded.hasDecodedInstructions = true;
    realDecoded.decodedInstructions = {"mov", "call", "jne", "ret", "sub"};
    decodedContext.functions.push_back(realDecoded);
    const auto decodedFeatures = features::FeatureExtractor{}.extract(decodedContext);
    assert(valueOf(decodedFeatures, "instructions.total") == 5.0);
    assert(valueOf(decodedFeatures, "instructions.calls") == 1.0);
    assert(valueOf(decodedFeatures, "instructions.jumps") == 1.0);
    assert(valueOf(decodedFeatures, "instructions.returns") == 1.0);

    return 0;
}
