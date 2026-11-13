
#include "lulz/analysis/EntropyAnalyzer.hpp"
#include "lulz/analysis/FunctionFinder.hpp"
#include "lulz/analysis/FunctionAnalysis.hpp"

#include "lulz/asm/x86/X86Decoder.hpp"

#include "lulz/formats/FormatDetector.hpp"
#include "lulz/formats/pe/PEParser.hpp"
#include "lulz/formats/pe/UnwindInfo.hpp"

#include "lulz/hex/HexParser.hpp"
#include "lulz/loaders/FileLoader.hpp"

#include "ai/core/AIContext.hpp"
#include "ai/analysis/AIAnalyzer.hpp"
#include "ai/analysis/AnalysisInput.hpp"
#include "ai/analysis/AnalysisResult.hpp"
#include "ai/analysis/AnalysisReport.hpp"
#include "ai/features/FeatureExtractor.hpp"
#include "ai/neural/NeuralNetwork.hpp"
#include "ai/training/Dataset.hpp"
#include "ai/training/Trainer.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// ==========================================
// Usage
// ==========================================

static void usage() {
    std::cout
        << "DLL LULZ AI v0.5.0\n"
        << "Commands:\n"
        << "  info <file>       identify format and entropy\n"
        << "  hex <file>        show first 256 bytes\n"
        << "  pe <file>         parse PE headers and sections\n"
        << "  disasm <hex>      decode supported x86-64 subset\n"
        << "  functions <file> find x64 functions\n"
        << "  unwind <file> [--json] parse x64 UNWIND_INFO\n"
        << "  analyze <file> [--json [output.json]] full analysis\n"
        << "  ai <file>         run static AI analysis and feature extraction\\n"
        << "  train <csv> <model> <targets> <hidden> [epochs] [rate]\\n"
        << "                    train a neural model from numeric CSV data\\n"
        << "  predict <model> <v1,v2,...> run neural inference\\n"
        << "\\nCSV: feature columns first, target columns last (header required).\n";
}

// ==========================================
// Helpers
// ==========================================

static std::string hexValue(std::uint64_t value) {
    std::string result;
    static constexpr char digits[] = "0123456789ABCDEF";

    do {
        result.insert(result.begin(), digits[value & 0xF]);
        value >>= 4;
    } while (value != 0);

    return "0x" + result;
}

static bool writeTextFile(
    const std::string& path,
    const std::string& content
) {
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        return false;
    }

    out << content << '\n';
    return static_cast<bool>(out);
}

// ==========================================
// Neural training and inference CLI
// ==========================================

static bool parsePositiveSize(const char* text, std::size_t& value) {
    try {
        std::size_t consumed = 0;
        const auto parsed = std::stoull(text, &consumed);
        if (consumed != std::string(text).size() || parsed == 0 || parsed > 1000000) return false;
        value = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) { return false; }
}

static bool parseFiniteDouble(const char* text, double& value) {
    try {
        std::size_t consumed = 0;
        value = std::stod(text, &consumed);
        return consumed == std::string(text).size() && std::isfinite(value);
    } catch (...) { return false; }
}

static bool parseInputVector(const std::string& text, std::vector<double>& values) {
    std::stringstream stream(text);
    std::string token;
    values.clear();
    while (std::getline(stream, token, ',')) {
        double value = 0.0;
        if (!parseFiniteDouble(token.c_str(), value)) return false;
        values.push_back(value);
    }
    return !values.empty() && text.back() != ',';
}

static int runTraining(int argc, char** argv) {
    if (argc < 6 || argc > 8) { usage(); return 2; }
    std::size_t targetColumns = 0, hiddenNeurons = 0, epochs = 500;
    double learningRate = 0.01;
    if (!parsePositiveSize(argv[4], targetColumns) ||
        !parsePositiveSize(argv[5], hiddenNeurons) ||
        (argc >= 7 && !parsePositiveSize(argv[6], epochs)) ||
        (argc >= 8 && !parseFiniteDouble(argv[7], learningRate)) ||
        !std::isfinite(learningRate) || learningRate <= 0.0 || learningRate > 10.0) {
        std::cerr << "Invalid training parameters.\n";
        return 2;
    }

    std::ifstream csv(argv[2]);
    if (!csv) {
        std::cerr << "Cannot open training dataset: " << argv[2] << '\n';
        return 1;
    }
    std::string error;
    auto dataset = lulz::ai::training::Dataset::loadCsv(csv, targetColumns, true, ',', &error);
    if (!dataset) {
        std::cerr << "Dataset error: " << error << '\n';
        return 2;
    }

    lulz::ai::neural::NeuralNetwork network(
        {dataset->featureCount(), hiddenNeurons, dataset->targetCount()},
        lulz::ai::neural::Activation::Relu,
        lulz::ai::neural::Activation::Linear);
    if (!network.valid()) {
        std::cerr << "Could not create neural network for this dataset.\n";
        return 2;
    }

    lulz::ai::training::TrainerOptions options;
    options.network.epochs = epochs;
    options.network.learningRate = learningRate;
    auto report = lulz::ai::training::Trainer::train(network, *dataset, options, &error);
    if (!report) {
        std::cerr << "Training failed: " << error << '\n';
        return 2;
    }

    std::ofstream modelFile(argv[3], std::ios::binary);
    if (!modelFile || !network.save(modelFile, &error)) {
        std::cerr << "Could not save model: " << (error.empty() ? argv[3] : error) << '\n';
        return 1;
    }

    std::cout << std::fixed << std::setprecision(6)
              << "Training complete\n"
              << "Dataset samples: " << dataset->size() << '\n'
              << "Input features: " << dataset->featureCount() << '\n'
              << "Output targets: " << dataset->targetCount() << '\n'
              << "Epochs: " << report->training.epochsCompleted << '\n'
              << "Initial MSE: " << report->training.initialLoss << '\n'
              << "Final training MSE: " << report->trainingMse << '\n'
              << "Validation samples: " << report->validationSamples << '\n';
    if (report->validationSamples != 0)
        std::cout << "Validation MSE: " << report->validationMse << '\n';
    std::cout << "Model saved: " << argv[3] << '\n';
    return 0;
}

static int runPrediction(const char* modelPath, const char* inputText) {
    std::ifstream modelFile(modelPath, std::ios::binary);
    if (!modelFile) {
        std::cerr << "Cannot open neural model: " << modelPath << '\n';
        return 1;
    }
    std::string error;
    auto network = lulz::ai::neural::NeuralNetwork::load(modelFile, &error);
    if (!network) {
        std::cerr << "Model load failed: " << error << '\n';
        return 2;
    }
    std::vector<double> input;
    if (!parseInputVector(inputText, input)) {
        std::cerr << "Input must be comma-separated finite numbers.\n";
        return 2;
    }
    auto prediction = network->predict(input, &error);
    if (!prediction) {
        std::cerr << "Inference failed: " << error << '\n';
        return 2;
    }
    std::cout << std::fixed << std::setprecision(8) << "Prediction:";
    for (double value : *prediction) std::cout << ' ' << value;
    std::cout << '\n';
    return 0;
}

// ==========================================
// AI Analysis
// ==========================================

static int runAI(
    const std::vector<std::uint8_t>& bytes,
    const std::string& filePath
) {
    using namespace lulz::ai;
    using namespace lulz::ai::analysis;
    using namespace lulz::ai::features;

    // Parse PE
    auto pe = lulz::parsePE(bytes);

    if (!pe) {
        std::cerr << "AI: PE parse error: "
                  << pe.error() << '\n';
        return 2;
    }

    // Analyze functions
    auto functionAnalysis =
        lulz::analyzePEFunctions(bytes, pe.value());

    if (!functionAnalysis) {
        std::cerr << "AI: Function analysis error: "
                  << functionAnalysis.error() << '\n';
        return 2;
    }

    // ======================================
    // Build Analysis Input
    // ======================================

    AnalysisInput input;
    input.sourceLabel = filePath;

    AIContext& context = input.context;

    context.filePath = filePath;
    context.format = "PE";
    context.architecture =
        pe.value().is64 ? "x64" : "x86";

    // Imports
    for (const auto& import : functionAnalysis.value().imports) {
        context.imports.push_back(import.name);
    }

    // Functions
    for (const auto& function :
         functionAnalysis.value().functions) {

        FunctionInfo info;

        info.name =
            "sub_" + hexValue(function.range.beginRva);

        info.address = function.range.beginRva;

        info.assembly.push_back(
            "Function range: " +
            hexValue(function.range.beginRva) + " - " +
            hexValue(function.range.endRva)
        );

        info.assembly.push_back(
            "Stack allocation: " +
            std::to_string(function.unwind.stackAllocation)
        );

        for (const auto& call : function.calls) {
            info.assembly.push_back(
                call.kind + " -> " + call.target
            );
        }

        context.functions.push_back(std::move(info));
    }

    // ======================================
    // Validate Context
    // ======================================

    std::string validationError;

    if (!context.validate(&validationError)) {
        std::cerr << "AI: Invalid context: "
                  << validationError << '\n';
        return 2;
    }

    // ======================================
    // Feature Extraction
    // ======================================

    FeatureExtractor featureExtractor;

    FeatureVector features =
        featureExtractor.extract(context);

    // ======================================
    // AI Analysis
    // ======================================

    AIAnalyzer analyzer;

    AnalysisResult result =
        analyzer.analyze(input);

    // ======================================
    // Output Metadata
    // ======================================

    std::cout
        << "\n====================================\n"
        << "       DLL LULZ AI ANALYSIS\n"
        << "====================================\n\n";

    std::cout
        << "File: " << filePath << '\n'
        << "Architecture: " << context.architecture << '\n'
        << "File size: " << bytes.size() << " bytes\n"
        << "Entropy: "
        << std::fixed
        << std::setprecision(4)
        << lulz::shannonEntropy(bytes)
        << " bits/byte\n"
        << "Functions: " << context.functions.size() << '\n'
        << "Imports: " << context.imports.size() << '\n'
        << "Extracted features: " << features.size()
        << "\n\n";

    // ======================================
    // Feature Report
    // ======================================

    std::cout
        << "========== AI FEATURES ==========\n";

    for (const auto& feature : features.values) {
        std::cout << feature.name << " = ";

        if (feature.type == FeatureType::Categorical) {
            std::cout << feature.textValue;
        } else {
            std::cout << feature.value;
        }

        std::cout << '\n';
    }

    std::cout
        << "=================================\n\n";

    // ======================================
    // Analysis Result
    // ======================================

    if (!result.success) {
        std::cerr
            << "AI Analysis failed: "
            << result.error << '\n';
        return 2;
    }

    std::cout << AnalysisReport::toText(result);

    // ======================================
    // Engine Information
    // ======================================

    std::cout
        << "\nAI Core: 0.1.0\n"
        << "AI Analysis: 0.1.0\n"
        << "AI Features: 0.1.0\n"
        << "AI Neural: 0.1.0 (predict command)\\n"
        << "AI Training: 0.1.0 (train command)\\n"
        << "Neural inference: use predict <model> <inputs>\n"
        << "Instruction disassembly: Not integrated\n"
        << "====================================\n";

    return 0;
}

// ==========================================
// Main
// ==========================================

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 0;
    }

    const std::string cmd = argv[1];

    if (cmd == "train") return runTraining(argc, argv);
    if (cmd == "predict") {
        if (argc != 4) { usage(); return 2; }
        return runPrediction(argv[2], argv[3]);
    }

    // ======================================
    // Disassembler
    // ======================================

    if (cmd == "disasm") {
        if (argc < 3) {
            usage();
            return 2;
        }

        auto bytes = lulz::parseHex(argv[2]);

        if (!bytes) {
            std::cerr << bytes.error() << '\n';
            return 2;
        }

        const auto instructions =
            lulz::disassembleX86Subset(bytes.value());

        for (const auto& instruction : instructions) {
            std::cout
                << std::hex
                << instruction.offset << ": "
                << instruction.text
                << (instruction.valid ? "" : " ; unknown byte")
                << '\n';
        }

        return 0;
    }

    if (argc < 3) {
        usage();
        return 2;
    }

    const std::string filePath = argv[2];

    // ======================================
    // Load File
    // ======================================

    auto loaded = lulz::loadFile(filePath);

    if (!loaded) {
        std::cerr << "File load error: "
                  << loaded.error() << '\n';
        return 1;
    }

    const auto& bytes = loaded.value();

    if (bytes.empty()) {
        std::cerr << "Error: file is empty\n";
        return 1;
    }

    // ======================================
    // AI
    // ======================================

    if (cmd == "ai") {
        return runAI(bytes, filePath);
    }

    // ======================================
    // INFO
    // ======================================

    if (cmd == "info") {
        std::cout
            << "Format: " << lulz::detectFormat(bytes)
            << "\nSize: " << bytes.size() << " bytes\n"
            << "Entropy: "
            << std::fixed
            << std::setprecision(4)
            << lulz::shannonEntropy(bytes)
            << " bits/byte\n";

        return 0;
    }

    // ======================================
    // HEX
    // ======================================

    if (cmd == "hex") {
        const std::size_t count =
            std::min<std::size_t>(256, bytes.size());

        std::vector<std::uint8_t> first(
            bytes.begin(),
            bytes.begin() + static_cast<std::ptrdiff_t>(count)
        );

        std::cout << lulz::formatHex(first) << '\n';

        return 0;
    }

    // ======================================
    // PE
    // ======================================

    if (cmd == "pe") {
        auto pe = lulz::parsePE(bytes);

        if (!pe) {
            std::cerr << "PE parse error: "
                      << pe.error() << '\n';
            return 2;
        }

        std::cout
            << "PE" << (pe.value().is64 ? "64" : "32")
            << " machine=" << hexValue(pe.value().machine)
            << " entry=" << hexValue(pe.value().entryPoint)
            << " imageBase=" << hexValue(pe.value().imageBase)
            << '\n';

        for (const auto& section : pe.value().sections) {
            std::cout
                << section.name
                << " RVA=" << hexValue(section.virtualAddress)
                << " raw=" << hexValue(section.rawOffset)
                << " size=" << hexValue(section.rawSize)
                << " flags=" << hexValue(section.characteristics)
                << '\n';
        }

        return 0;
    }

    // ======================================
    // UNWIND
    // ======================================

    if (cmd == "unwind") {
        auto pe = lulz::parsePE(bytes);

        if (!pe) {
            std::cerr << "PE parse error: "
                      << pe.error() << '\n';
            return 2;
        }

        auto runtime =
            lulz::parsePEExceptionDirectory(bytes, pe.value());

        if (!runtime) {
            std::cerr << ".pdata error: "
                      << runtime.error() << '\n';
            return 2;
        }

        const bool json =
            argc >= 4 && std::string(argv[3]) == "--json";

        std::size_t ok = 0;
        std::size_t failed = 0;

        std::vector<std::string> jsonRecords;

        if (!json) {
            std::cout
                << "UNWIND_INFO records: "
                << runtime.value().size() << '\n';
        }

        for (const auto& function : runtime.value()) {
            auto unwind =
                lulz::parsePEUnwindInfo(bytes, pe.value(), function);

            if (!unwind) {
                ++failed;

                if (!json) {
                    std::cout
                        << "[ERROR] "
                        << hexValue(function.beginRva)
                        << ": " << unwind.error() << '\n';
                }

                continue;
            }

            ++ok;

            if (json) {
                jsonRecords.push_back(
                    lulz::unwindInfoToJson(function, unwind.value())
                );
            } else {
                std::cout
                    << "function "
                    << hexValue(function.beginRva)
                    << " - "
                    << hexValue(function.endRva)
                    << " | version="
                    << std::dec
                    << unsigned(unwind.value().version)
                    << " prolog="
                    << unsigned(unwind.value().prologSize)
                    << " stack="
                    << unwind.value().stackAllocation
                    << " bytes\n";

                for (const auto& op : unwind.value().operations) {
                    std::cout
                        << "  +" << unsigned(op.codeOffset)
                        << " " << op.name
                        << ": " << op.detail << '\n';
                }
            }
        }

        if (json) {
            std::cout << "[\n";

            for (std::size_t i = 0; i < jsonRecords.size(); ++i) {
                std::cout
                    << jsonRecords[i]
                    << (i + 1 < jsonRecords.size() ? ",\n" : "\n");
            }

            std::cout << "]\n";
        } else {
            std::cout
                << "\nParsed: " << ok
                << ", errors: " << failed << '\n';
        }

        return ok == 0 ? 2 : 0;
    }

    // ======================================
    // FULL ANALYSIS
    // ======================================

    if (cmd == "analyze") {
        auto pe = lulz::parsePE(bytes);

        if (!pe) {
            std::cerr << "PE parse error: "
                      << pe.error() << '\n';
            return 2;
        }

        auto analysis =
            lulz::analyzePEFunctions(bytes, pe.value());

        if (!analysis) {
            std::cerr << "Function analysis error: "
                      << analysis.error() << '\n';
            return 2;
        }

        const std::string report =
            lulz::functionAnalysisToJson(
                analysis.value(),
                pe.value()
            );

        if (argc >= 4 && std::string(argv[3]) == "--json") {
            if (argc >= 5) {
                if (!writeTextFile(argv[4], report)) {
                    std::cerr
                        << "Cannot write JSON output: "
                        << argv[4] << '\n';
                    return 1;
                }

                std::cout
                    << "JSON report written: "
                    << argv[4] << '\n';
            } else {
                std::cout << report << '\n';
            }

            return 0;
        }

        std::cout
            << "Functions: "
            << analysis.value().functions.size()
            << "\nImports: "
            << analysis.value().imports.size()
            << "\nUnresolved calls: "
            << analysis.value().unresolvedCalls
            << '\n';

        for (const auto& function : analysis.value().functions) {
            std::cout
                << "function "
                << hexValue(function.range.beginRva)
                << "-"
                << hexValue(function.range.endRva)
                << " stack="
                << std::dec
                << function.unwind.stackAllocation
                << " bytes calls="
                << function.calls.size()
                << '\n';
        }

        return 0;
    }

    // ======================================
    // FUNCTIONS
    // ======================================

    if (cmd == "functions") {
        auto pe = lulz::parsePE(bytes);

        if (pe && pe.value().is64) {
            auto runtime =
                lulz::parsePEExceptionDirectory(bytes, pe.value());

            if (runtime) {
                std::cout
                    << "Source: PE x64 Exception Directory (.pdata)\n"
                    << "Runtime functions: "
                    << std::dec
                    << runtime.value().size() << '\n';

                for (const auto& function : runtime.value()) {
                    std::cout
                        << "function "
                        << hexValue(function.beginRva)
                        << " - "
                        << hexValue(function.endRva)
                        << " unwind="
                        << hexValue(function.unwindInfoRva)
                        << '\n';
                }
            } else {
                std::cout
                    << "PE .pdata unavailable: "
                    << runtime.error() << '\n';
            }
        } else if (!pe) {
            std::cout
                << "PE parsing unavailable: "
                << pe.error() << '\n';
        }

        const auto candidates =
            lulz::findX64FunctionCandidates(bytes);

        std::cout
            << "\nHeuristic candidates: "
            << std::dec << candidates.size() << '\n';

        for (const auto& function : candidates) {
            std::cout
                << "candidate "
                << hexValue(function.offset)
                << " : " << function.reason << '\n';
        }

        return 0;
    }

    // ======================================
    // UNKNOWN COMMAND
    // ======================================

    usage();
    return 2;
}
