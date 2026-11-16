#include "ai/builder/BuilderLearning.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

int main() {
    using namespace lulz::ai::builder;
    const auto root = std::filesystem::temp_directory_path() / "lulz_builder_learning_test";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    const auto dataset = root / "training.json";
    {
        std::ofstream out(dataset);
        out << R"({"examples":[
          {"analysis":{"format":"PE32+ x64","functions":[{"begin_rva":4096,"end_rva":4112,"calls":[{"resolved":true}]}],"imports":[{"module":"KERNEL32.dll","name":"ExitProcess"}],"decoded_instructions":12},"targets":{"assembly_valid":1,"repair_needed":0}},
          {"analysis":{"format":"PE32","functions":[],"imports":[],"analysis_warnings":["bad range"],"decoded_instructions":0},"targets":{"assembly_valid":0,"repair_needed":1}},
          {"analysis":{"format":"PE32+ x64","functions":[{"begin_rva":4096,"end_rva":4128}],"imports":[{"module":"USER32.dll","name":"MessageBoxW"}]},"targets":{"assembly_valid":1,"repair_needed":0}},
          {"analysis":{"format":"PE32","functions":[{"begin_rva":100,"end_rva":50}],"imports":[{"module":"KERNEL32.dll"}],"warnings":["warning"]},"targets":{"assembly_valid":0,"repair_needed":1}}
        ]})";
    }
    BuilderTrainingOptions options;
    options.network.epochs = 20;
    options.network.learningRate = 0.03;
    std::string error;
    const auto trained = BuilderLearning::trainDataset(dataset, root / "models", options, &error);
    assert(trained && trained->examples == 4);
    assert(std::filesystem::exists(root / "models" / "builder_assembly.lzb"));
    assert(std::filesystem::exists(root / "models" / "builder_repair.lzb"));
    auto loaded = BuilderLearning::load(root / "models" / "builder_assembly.lzb",
                                        root / "models" / "builder_repair.lzb", &error);
    assert(loaded);
    const auto parsed = JsonParser(R"({"format":"PE32+ x64","functions":[{"begin_rva":4096,"end_rva":4112}],"imports":[]})").parse();
    assert(parsed.success);
    const auto prediction = loaded->evaluate(parsed.value, &error);
    assert(prediction);
    assert(prediction->assemblyScore >= 0.0 && prediction->assemblyScore <= 1.0);
    assert(prediction->repairScore >= 0.0 && prediction->repairScore <= 1.0);
    assert(BuilderLearning::extractFeatures(parsed.value).size() == kBuilderFeatureCount);

    // Real Analyzer reports encode function RVAs as hexadecimal strings.
    const auto hexParsed = JsonParser(
        R"({"format":"PE32+ x64","functions":[{"begin_rva":"0x1010","end_rva":"0x115a","calls":[]}],"imports":[]})"
    ).parse();
    assert(hexParsed.success);
    const auto hexFeatures = BuilderLearning::extractFeatures(hexParsed.value);
    assert(hexFeatures.size() == kBuilderFeatureCount);
    assert(hexFeatures[14] == 0.0); // A valid hexadecimal range is not malformed.
    std::filesystem::remove_all(root, ec);
    std::cout << "Builder learning tests passed\n";
    return 0;
}
