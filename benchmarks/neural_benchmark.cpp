#include "ai/neural/NeuralNetwork.hpp"

#include <chrono>
#include <cmath>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

double seconds(Clock::duration duration) {
    return std::chrono::duration<double>(duration).count();
}

double targetFor(const std::vector<double>& x, std::size_t output) {
    const double a = x[0];
    const double b = x[1];
    const double c = x[2];
    switch (output) {
    case 0: return 0.5 * a - 0.25 * b + 0.1 * c;
    case 1: return std::tanh(a + b - c);
    default: return 0.2 * a * b + 0.3 * c;
    }
}

} // namespace

int main() {
    constexpr std::size_t sampleCount = 2048;
    constexpr std::size_t inputCount = 8;
    constexpr std::size_t outputCount = 3;
    constexpr std::size_t epochs = 40;

    using lulz::ai::neural::Activation;
    using lulz::ai::neural::NeuralNetwork;
    using lulz::ai::neural::TrainingOptions;

    std::vector<std::vector<double>> inputs;
    std::vector<std::vector<double>> targets;
    inputs.reserve(sampleCount);
    targets.reserve(sampleCount);

    const auto dataStart = Clock::now();
    for (std::size_t i = 0; i < sampleCount; ++i) {
        std::vector<double> x(inputCount);
        for (std::size_t j = 0; j < inputCount; ++j) {
            const auto value = static_cast<int>((i * 37 + j * 19) % 101);
            x[j] = (static_cast<double>(value) - 50.0) / 50.0;
        }
        std::vector<double> y(outputCount);
        for (std::size_t k = 0; k < outputCount; ++k)
            y[k] = targetFor(x, k);
        inputs.push_back(std::move(x));
        targets.push_back(std::move(y));
    }
    const double dataSeconds = seconds(Clock::now() - dataStart);

    NeuralNetwork network({inputCount, 32, 16, outputCount},
                          Activation::Relu, Activation::Linear, 0x4c554c5a);
    if (!network.valid()) {
        std::cerr << "Failed to initialize benchmark network\n";
        return 1;
    }

    TrainingOptions options;
    options.epochs = epochs;
    options.learningRate = 0.005;
    options.shuffle = true;
    options.seed = 0x42454e43;

    const auto trainStart = Clock::now();
    const auto report = network.train(inputs, targets, options);
    const double trainSeconds = seconds(Clock::now() - trainStart);
    if (!report) {
        std::cerr << "Training failed: invalid workload or training options\n";
        return 1;
    }

    const auto inferenceStart = Clock::now();
    std::size_t predictions = 0;
    double checksum = 0.0;
    for (const auto& input : inputs) {
        const auto result = network.predict(input);
        if (!result || result->size() != outputCount) {
            std::cerr << "Inference failed\n";
            return 1;
        }
        for (double value : *result) {
            if (!std::isfinite(value)) {
                std::cerr << "Inference produced a non-finite value\n";
                return 1;
            }
            checksum += value;
        }
        ++predictions;
    }
    const double inferenceSeconds = seconds(Clock::now() - inferenceStart);

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "DLL LULZ AI neural microbenchmark\n"
              << "topology: 8-32-16-3\n"
              << "samples: " << sampleCount << "\n"
              << "epochs: " << report->epochsCompleted << "\n"
              << "dataset_generation_seconds: " << dataSeconds << "\n"
              << "training_seconds: " << trainSeconds << "\n"
              << "training_samples_per_second: "
              << (trainSeconds > 0.0 ? (sampleCount * report->epochsCompleted) / trainSeconds : 0.0)
              << "\n"
              << "inference_seconds: " << inferenceSeconds << "\n"
              << "inference_samples_per_second: "
              << (inferenceSeconds > 0.0 ? predictions / inferenceSeconds : 0.0)
              << "\n"
              << "initial_loss: " << report->initialLoss << "\n"
              << "final_loss: " << report->finalLoss << "\n"
              << "inference_checksum: " << checksum << "\n";
    return 0;
}
