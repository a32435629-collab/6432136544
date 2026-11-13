#pragma once

#include "Dataset.hpp"
#include "ai/neural/NeuralNetwork.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace lulz::ai::training {

struct TrainerOptions {
    neural::TrainingOptions network;
    double validationFraction = 0.2;
    std::uint32_t splitSeed = 0x54524149;
};

struct TrainerReport {
    neural::TrainingReport training;
    std::size_t trainingSamples = 0;
    std::size_t validationSamples = 0;
    double trainingMse = 0.0;
    double validationMse = 0.0;
};

class Trainer {
public:
    static std::optional<TrainerReport> train(
        neural::NeuralNetwork& network,
        const Dataset& dataset,
        const TrainerOptions& options = {},
        std::string* error = nullptr);
};

} // namespace lulz::ai::training
