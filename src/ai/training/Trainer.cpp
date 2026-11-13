#include "Trainer.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <random>
#include <vector>

namespace lulz::ai::training {
namespace {

void setError(std::string* error, const char* message) {
    if (error) *error = message;
}

double calculateMse(const neural::NeuralNetwork& network,
                    const Dataset& dataset,
                    const std::vector<std::size_t>& indices) {
    double sum = 0.0;
    std::size_t count = 0;
    for (const auto index : indices) {
        const auto& sample = dataset.samples()[index];
        const auto prediction = network.predict(sample.inputs);
        if (!prediction) return std::numeric_limits<double>::infinity();
        for (std::size_t i = 0; i < prediction->size(); ++i) {
            const double difference = (*prediction)[i] - sample.targets[i];
            sum += difference * difference;
            ++count;
        }
    }
    return count == 0 ? 0.0 : sum / static_cast<double>(count);
}

} // namespace

std::optional<TrainerReport> Trainer::train(
    neural::NeuralNetwork& network,
    const Dataset& dataset,
    const TrainerOptions& options,
    std::string* error) {
    if (!network.valid() || dataset.empty()) {
        setError(error, "A valid network and a non-empty dataset are required");
        return std::nullopt;
    }
    if (network.inputSize() != dataset.featureCount() ||
        network.outputSize() != dataset.targetCount()) {
        setError(error, "Dataset dimensions do not match neural network topology");
        return std::nullopt;
    }
    if (!std::isfinite(options.validationFraction) ||
        options.validationFraction < 0.0 ||
        options.validationFraction >= 0.5) {
        setError(error, "Validation fraction must be in the range [0, 0.5)");
        return std::nullopt;
    }
    if (options.validationFraction > 0.0 && dataset.size() < 2) {
        setError(error, "At least two samples are required for validation splitting");
        return std::nullopt;
    }

    std::vector<std::size_t> indices(dataset.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::mt19937 rng(options.splitSeed);
    std::shuffle(indices.begin(), indices.end(), rng);

    std::size_t validationCount = 0;
    if (options.validationFraction > 0.0) {
        validationCount = std::max<std::size_t>(
            1, static_cast<std::size_t>(
                std::round(dataset.size() * options.validationFraction)));
        validationCount = std::min(validationCount, dataset.size() - 1);
    }

    std::vector<std::vector<double>> inputs;
    std::vector<std::vector<double>> targets;
    inputs.reserve(dataset.size() - validationCount);
    targets.reserve(dataset.size() - validationCount);
    for (std::size_t i = validationCount; i < indices.size(); ++i) {
        const auto& sample = dataset.samples()[indices[i]];
        inputs.push_back(sample.inputs);
        targets.push_back(sample.targets);
    }

    auto training = network.train(inputs, targets, options.network, error);
    if (!training) return std::nullopt;

    TrainerReport report;
    report.training = *training;
    report.trainingSamples = inputs.size();
    report.validationSamples = validationCount;
    std::vector<std::size_t> trainingIndices(indices.begin() +
        static_cast<std::ptrdiff_t>(validationCount), indices.end());
    report.trainingMse = calculateMse(network, dataset, trainingIndices);
    if (validationCount != 0) {
        std::vector<std::size_t> validationIndices(indices.begin(),
            indices.begin() + static_cast<std::ptrdiff_t>(validationCount));
        report.validationMse = calculateMse(network, dataset, validationIndices);
    } else {
        report.validationMse = 0.0;
    }
    if (!std::isfinite(report.trainingMse) ||
        !std::isfinite(report.validationMse)) {
        setError(error, "Training produced non-finite evaluation metrics");
        return std::nullopt;
    }
    return report;
}

} // namespace lulz::ai::training
