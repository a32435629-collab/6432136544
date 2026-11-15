#include "lulz/analysis/FunctionAnalysis.hpp"
#include "lulz/formats/pe/PEParser.hpp"
#include "lulz/loaders/FileLoader.hpp"
#include "ai/core/AIContext.hpp"
#include "ai/features/FeatureExtractor.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <utility>

namespace {
const std::vector<std::string> kFeatureNames = {
    "imports.total", "functions.total", "instructions.available",
    "imports.dynamic_resolution", "imports.memory_operations",
    "imports.remote_memory", "imports.network", "imports.process",
    "imports.crypto", "imports.persistence", "imports.anti_analysis",
    "imports.remote_memory_ratio", "imports.network_ratio",
    "functions.decoded", "functions.undecoded", "functions.decoded_ratio",
    "functions.average_size", "functions.min_size", "functions.max_size",
    "functions.empty_decoded", "instructions.decoded_functions",
    "instructions.total", "instructions.calls", "instructions.jumps",
    "instructions.stack_operations", "instructions.returns",
    "instructions.unparsed_text", "instructions.control_flow"
};

bool writeFeatures(const std::string& filePath, const std::string& label, std::ostream& output,
                   std::string& error) {
    auto loaded = lulz::loadFile(filePath);
    if (!loaded) { error = "Cannot read " + filePath + ": " + loaded.error(); return false; }
    auto pe = lulz::parsePE(loaded.value());
    if (!pe) { error = "Not a supported PE file " + filePath + ": " + pe.error(); return false; }
    auto analysis = lulz::analyzePEFunctions(loaded.value(), pe.value());
    if (!analysis) { error = "PE analysis failed for " + filePath + ": " + analysis.error(); return false; }

    lulz::ai::AIContext context;
    context.filePath = filePath;
    context.format = "PE";
    context.architecture = pe.value().is64 ? "x64" : "x86";
    for (const auto& import : analysis.value().imports)
        context.imports.push_back(import.name);
    for (const auto& function : analysis.value().functions) {
        lulz::ai::FunctionInfo info;
        info.name = "function";
        for (const auto& instruction : function.instructions)
            info.decodedInstructions.push_back(instruction.mnemonic);
        info.hasDecodedInstructions = !info.decodedInstructions.empty();
        context.functions.push_back(std::move(info));
    }

    const auto features = lulz::ai::features::FeatureExtractor{}.extract(context);
    output << label;
    std::size_t written = 0;
    for (const auto& feature : features.values) {
        if (feature.type != lulz::ai::features::FeatureType::Numeric) continue;
        output << ',' << feature.value;
        ++written;
    }
    output << '\n';
    if (written != kFeatureNames.size() || !output) {
        error = "Feature schema/output failure for " + filePath;
        return false;
    }
    return true;
}
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: lulz_dataset <manifest.csv> <dataset.csv>\n"
                  << "Manifest format: label,path (one PE file per line; labels: benign or malicious)\n";
        return 2;
    }
    const std::filesystem::path manifestPath = argv[1];
    std::ifstream manifest(manifestPath);
    if (!manifest) { std::cerr << "Cannot open manifest: " << argv[1] << '\n'; return 2; }
    std::ofstream output(argv[2], std::ios::trunc);
    if (!output) { std::cerr << "Cannot create dataset: " << argv[2] << '\n'; return 2; }

    output << "label";
    for (const auto& name : kFeatureNames) output << ',' << name;
    output << '\n';

    std::string line;
    if (!std::getline(manifest, line) || line != "label,path") {
        std::cerr << "Manifest must start with the exact header: label,path\n";
        return 2;
    }
    std::size_t processed = 0, lineNumber = 1;
    while (std::getline(manifest, line)) {
        ++lineNumber;
        if (line.empty()) continue;
        const auto comma = line.find(',');
        if (comma == std::string::npos || line.find(',', comma + 1) != std::string::npos) {
            std::cerr << "Invalid manifest row at line " << lineNumber << " (paths containing commas are unsupported)\n";
            return 2;
        }
        const std::string label = line.substr(0, comma);
        if (label != "benign" && label != "malicious") {
            std::cerr << "Invalid label at line " << lineNumber << '\n';
            return 2;
        }
        std::filesystem::path filePath = line.substr(comma + 1);
        if (filePath.empty()) { std::cerr << "Missing path at line " << lineNumber << '\n'; return 2; }
        if (filePath.is_relative()) filePath = manifestPath.parent_path() / filePath;
        std::string error;
        if (!writeFeatures(filePath.string(), label, output, error)) {
            std::cerr << error << '\n';
            return 2;
        }
        ++processed;
        std::cout << "Processed " << processed << ": " << filePath.string() << '\n';
    }
    if (!output) { std::cerr << "Failed writing dataset CSV\n"; return 2; }
    std::cout << "Dataset written: " << argv[2] << " (" << processed << " PE files)\n";
    std::cout << "Files were read and statically parsed only; none were executed.\n";
    return 0;
}
