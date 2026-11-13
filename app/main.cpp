
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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
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
        << "  ai <file>         run AI analysis and feature extraction\n";
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
        << "Neural inference: Not performed\n"
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
