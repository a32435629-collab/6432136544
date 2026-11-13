#include "ai/neural/NeuralNetwork.hpp"
#include <cassert>
#include <cmath>
#include <sstream>
#include <string>
#include <vector>
using lulz::ai::neural::Activation;
using lulz::ai::neural::NeuralNetwork;
using lulz::ai::neural::TrainingOptions;
int main() {
    NeuralNetwork model({1, 1}, Activation::Linear, Activation::Linear, 7);
    assert(model.valid() && model.inputSize() == 1 && model.outputSize() == 1);
    const std::vector<std::vector<double>> inputs{{-2.0},{-1.0},{0.0},{1.0},{2.0}};
    const std::vector<std::vector<double>> targets{{-3.0},{-1.0},{1.0},{3.0},{5.0}};
    TrainingOptions options;
    options.epochs = 1200;
    options.learningRate = 0.03;
    options.seed = 123;
    auto report = model.train(inputs, targets, options);
    assert(report && report->epochsCompleted == options.epochs);
    assert(report->finalLoss < report->initialLoss * 0.001);
    auto prediction = model.predict({3.0});
    assert(prediction && prediction->size() == 1);
    assert(std::abs((*prediction)[0] - 7.0) < 0.1);
    assert(!model.predict({1.0, 2.0}));
    assert(!model.predict({std::nan("")}));

    std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
    assert(model.save(stream));
    stream.seekg(0);
    auto restored = NeuralNetwork::load(stream);
    assert(restored && restored->topology() == model.topology());
    auto restoredPrediction = restored->predict({3.0});
    assert(restoredPrediction && std::abs((*restoredPrediction)[0] - (*prediction)[0]) < 1e-12);

    std::stringstream truncated("LU", std::ios::in | std::ios::binary);
    assert(!NeuralNetwork::load(truncated));
    NeuralNetwork invalid({1, 0, 2});
    assert(!invalid.valid());
    assert(!invalid.train(inputs, targets, options));
}
