#include "ai/builder/BuilderLearning.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <limits>
#include <utility>

namespace lulz::ai::builder {
namespace {

void setError(std::string* out, const std::string& message) { if (out) *out = message; }

const JsonValue* child(const JsonValue* value, const char* key) {
    return value ? value->get(key) : nullptr;
}

std::size_t countArray(const JsonValue* value) {
    const auto* array = value ? value->array() : nullptr;
    return array ? array->size() : 0;
}

double number(const JsonValue* value, double fallback = 0.0) {
    if (!value) return fallback;
    if (const auto* n = std::get_if<double>(&value->value)) return *n;
    return fallback;
}

bool boolean(const JsonValue* value) {
    if (!value) return false;
    if (const auto* b = std::get_if<bool>(&value->value)) return *b;
    return false;
}

double scaledCount(std::size_t value) {
    return std::min(1.0, std::log1p(static_cast<double>(value)) / 16.0);
}

bool saveModel(const neural::NeuralNetwork& model, const std::filesystem::path& path,
               const char* role, std::string* error) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { setError(error, "Cannot create model file: " + path.string()); return false; }
    out.write("LULZBL01", 8);
    const std::string tag(role);
    out.put(static_cast<char>(tag.size()));
    out.write(tag.data(), static_cast<std::streamsize>(tag.size()));
    if (!model.save(out, error) || !out) {
        if (error && error->empty()) *error = "Failed to save model: " + path.string();
        return false;
    }
    return true;
}

std::optional<neural::NeuralNetwork> loadModel(const std::filesystem::path& path,
                                                const char* expectedRole,
                                                std::string* error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { setError(error, "Cannot open model file: " + path.string()); return std::nullopt; }
    char magic[8]{};
    in.read(magic, 8);
    const int tagLength = in.get();
    if (!in || std::string(magic, 8) != "LULZBL01" || tagLength <= 0 || tagLength > 32) {
        setError(error, "Invalid Builder model header: " + path.string()); return std::nullopt;
    }
    std::string role(static_cast<std::size_t>(tagLength), '\0');
    in.read(role.data(), tagLength);
    if (!in || role != expectedRole) {
        setError(error, "Builder model type mismatch: expected " + std::string(expectedRole)); return std::nullopt;
    }
    auto model = neural::NeuralNetwork::load(in, error);
    if (!model) return std::nullopt;
    if (model->inputSize() != kBuilderFeatureCount || model->outputSize() != 1) {
        setError(error, "Builder model feature schema is incompatible"); return std::nullopt;
    }
    return model;
}

} // namespace

BuilderLearning::BuilderLearning(neural::NeuralNetwork assembly, neural::NeuralNetwork repair)
    : assembly_(std::move(assembly)), repair_(std::move(repair)) {}

std::vector<double> BuilderLearning::extractFeatures(const JsonValue& report) {
    const auto* functions = child(&report, "functions");
    const auto* imports = child(&report, "imports");
    const auto* metadata = child(&report, "pe_metadata");
    const auto* exports = child(metadata, "exports");
    const auto* relocations = child(metadata, "base_relocations");
    const auto* debug = child(metadata, "debug_entries");
    const auto* certificates = child(metadata, "certificates");
    const auto* tls = child(metadata, "tls");
    const auto* callbacks = child(tls, "callbacks");
    const auto* warnings = child(&report, "analysis_warnings");
    if (!warnings) warnings = child(&report, "warnings");

    const std::size_t functionCount = countArray(functions);
    const std::size_t importCount = countArray(imports);
    const std::size_t warningCount = countArray(warnings);
    std::size_t unresolvedCalls = 0, totalCalls = 0, malformedRanges = 0, missingImportFields = 0;
    if (const auto* fs = functions ? functions->array() : nullptr) {
        for (const auto& fn : *fs) {
            const auto* calls = child(&fn, "calls");
            if (const auto* cs = calls ? calls->array() : nullptr) {
                totalCalls += cs->size();
                for (const auto& call : *cs)
                    if (child(&call, "resolved") && !boolean(child(&call, "resolved"))) ++unresolvedCalls;
            }
            const double begin = number(child(&fn, "begin_rva"), -1.0);
            const double end = number(child(&fn, "end_rva"), -1.0);
            if (begin < 0.0 || end <= begin) ++malformedRanges;
        }
    }
    if (const auto* is = imports ? imports->array() : nullptr) {
        for (const auto& imp : *is)
            if (!child(&imp, "module") || !child(&imp, "name")) ++missingImportFields;
    }

    const auto* formatValue = child(&report, "format");
    const std::string format = formatValue && formatValue->string() ? *formatValue->string() : std::string{};
    const bool pe32plus = format.find("PE32+") != std::string::npos;
    const bool pe32 = !pe32plus && format.find("PE32") != std::string::npos;
    const double instructionCount = number(child(&report, "decoded_instructions"));
    const double unresolvedFromRoot = number(child(&report, "unresolved_calls"));

    return {
        pe32 ? 1.0 : 0.0,
        pe32plus ? 1.0 : 0.0,
        scaledCount(functionCount),
        scaledCount(importCount),
        scaledCount(countArray(exports)),
        scaledCount(countArray(relocations)),
        scaledCount(countArray(debug)),
        scaledCount(countArray(certificates)),
        scaledCount(countArray(callbacks)),
        scaledCount(warningCount),
        scaledCount(std::max(unresolvedCalls, static_cast<std::size_t>(std::max(0.0, unresolvedFromRoot)))),
        scaledCount(static_cast<std::size_t>(std::max(0.0, instructionCount))),
        functionCount == 0 ? 1.0 : 0.0,
        scaledCount(missingImportFields),
        scaledCount(malformedRanges),
        scaledCount(totalCalls),
        totalCalls == 0 ? 0.0 : static_cast<double>(unresolvedCalls) / static_cast<double>(totalCalls)
    };
}

std::optional<BuilderTrainingReport> BuilderLearning::trainDataset(
    const std::filesystem::path& dataset,
    const std::filesystem::path& outputDirectory,
    const BuilderTrainingOptions& options,
    std::string* error) {
    std::ifstream input(dataset, std::ios::binary);
    if (!input) { setError(error, "Cannot open training dataset: " + dataset.string()); return std::nullopt; }
    std::string json((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const auto parsed = JsonParser(std::move(json)).parse();
    if (!parsed.success) { setError(error, "Dataset JSON error at " + std::to_string(parsed.errorOffset) + ": " + parsed.error); return std::nullopt; }
    const auto* examplesValue = parsed.value.get("examples");
    const auto* examples = examplesValue ? examplesValue->array() : nullptr;
    if (!examples || examples->size() < 2 || examples->size() > 100000) {
        setError(error, "Dataset must contain 2..100000 items in the 'examples' array"); return std::nullopt;
    }
    if (options.hiddenNeurons == 0 || options.hiddenNeurons > 256) {
        setError(error, "hiddenNeurons must be between 1 and 256"); return std::nullopt;
    }

    std::vector<std::vector<double>> xs, assemblyTargets, repairTargets;
    xs.reserve(examples->size()); assemblyTargets.reserve(examples->size()); repairTargets.reserve(examples->size());
    for (std::size_t i = 0; i < examples->size(); ++i) {
        const auto& example = (*examples)[i];
        const auto* analysis = child(&example, "analysis");
        const auto* targets = child(&example, "targets");
        const auto* assembly = child(targets, "assembly_valid");
        const auto* repair = child(targets, "repair_needed");
        if (!analysis || !analysis->isObject() || !assembly || !assembly->isNumber() ||
            !repair || !repair->isNumber()) {
            setError(error, "Example " + std::to_string(i) + " requires object 'analysis' and numeric targets.assembly_valid / targets.repair_needed"); return std::nullopt;
        }
        const double a = number(assembly, -1.0), r = number(repair, -1.0);
        if ((a != 0.0 && a != 1.0) || (r != 0.0 && r != 1.0)) {
            setError(error, "Example " + std::to_string(i) + " targets must be 0 or 1"); return std::nullopt;
        }
        xs.push_back(extractFeatures(*analysis));
        assemblyTargets.push_back({a});
        repairTargets.push_back({r});
    }

    neural::NeuralNetwork assemblyModel({kBuilderFeatureCount, options.hiddenNeurons, 1},
        neural::Activation::Relu, neural::Activation::Sigmoid, options.network.seed);
    neural::NeuralNetwork repairModel({kBuilderFeatureCount, options.hiddenNeurons, 1},
        neural::Activation::Relu, neural::Activation::Sigmoid, options.network.seed ^ 0x9e3779b9u);
    auto assemblyReport = assemblyModel.train(xs, assemblyTargets, options.network, error);
    if (!assemblyReport) return std::nullopt;
    auto repairReport = repairModel.train(xs, repairTargets, options.network, error);
    if (!repairReport) return std::nullopt;

    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);
    if (ec) { setError(error, "Cannot create model directory: " + ec.message()); return std::nullopt; }
    if (!saveModel(assemblyModel, outputDirectory / "builder_assembly.lzb", "assembly", error) ||
        !saveModel(repairModel, outputDirectory / "builder_repair.lzb", "repair", error))
        return std::nullopt;

    if (error) error->clear();
    BuilderTrainingReport result;
    result.examples = examples->size();
    result.assembly = *assemblyReport;
    result.repair = *repairReport;
    return result;
}

std::optional<BuilderLearning> BuilderLearning::load(
    const std::filesystem::path& assemblyPath,
    const std::filesystem::path& repairPath,
    std::string* error) {
    auto assembly = loadModel(assemblyPath, "assembly", error);
    if (!assembly) return std::nullopt;
    auto repair = loadModel(repairPath, "repair", error);
    if (!repair) return std::nullopt;
    return BuilderLearning(std::move(*assembly), std::move(*repair));
}

std::optional<BuilderLearningResult> BuilderLearning::evaluate(
    const JsonValue& report, std::string* error) const {
    const auto features = extractFeatures(report);
    auto assembly = assembly_.predict(features, error);
    if (!assembly) return std::nullopt;
    auto repair = repair_.predict(features, error);
    if (!repair) return std::nullopt;
    if (assembly->empty() || repair->empty()) {
        setError(error, "Builder model returned an empty result"); return std::nullopt;
    }
    if (error) error->clear();
    return BuilderLearningResult{assembly->front(), repair->front()};
}

} // namespace lulz::ai::builder
