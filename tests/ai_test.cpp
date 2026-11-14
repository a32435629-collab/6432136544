#include "ai/core/AIEngine.hpp"
#include "ai/analysis/AIAnalyzer.hpp"
#include "ai/analysis/AnalysisReport.hpp"
#include "ai/features/FeatureExtractor.hpp"

#include <algorithm>
#include <cassert>
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

    return 0;
}
