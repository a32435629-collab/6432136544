#pragma once

#include "ai/builder/Json.hpp"
#include "ai/neural/NeuralNetwork.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace lulz::ai::builder {

inline constexpr std::size_t kBuilderFeatureCount = 17;

struct BuilderTrainingOptions {
    neural::TrainingOptions network;
    std::size_t hiddenNeurons = 12;
};

struct BuilderTrainingReport {
    std::size_t examples = 0;
    neural::TrainingReport assembly;
    neural::TrainingReport repair;
};

struct BuilderLearningResult {
    double assemblyScore = 0.0;
    double repairScore = 0.0;
};

class BuilderLearning {
public:
    static std::optional<BuilderTrainingReport> trainDataset(
        const std::filesystem::path& dataset,
        const std::filesystem::path& outputDirectory,
        const BuilderTrainingOptions& options = {},
        std::string* error = nullptr);

    static std::optional<BuilderLearning> load(
        const std::filesystem::path& assemblyModel,
        const std::filesystem::path& repairModel,
        std::string* error = nullptr);

    std::optional<BuilderLearningResult> evaluate(
        const JsonValue& analyzerReport,
        std::string* error = nullptr) const;

    static std::vector<double> extractFeatures(const JsonValue& analyzerReport);

private:
    neural::NeuralNetwork assembly_;
    neural::NeuralNetwork repair_;
    BuilderLearning(neural::NeuralNetwork assembly, neural::NeuralNetwork repair);
};

} // namespace lulz::ai::builder
