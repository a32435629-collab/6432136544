#include "ai/neural/NeuralNetwork.hpp"
#include "ai/training/Dataset.hpp"
#include "ai/training/Trainer.hpp"

#include <cassert>
#include <cmath>
#include <limits>
#include <sstream>
#include <string>

using lulz::ai::neural::Activation;
using lulz::ai::neural::NeuralNetwork;
using lulz::ai::training::Dataset;
using lulz::ai::training::Trainer;
using lulz::ai::training::TrainerOptions;

int main() {
    std::istringstream csv(
        "length,imports,label\r\n"
        "1,2,0\r\n"
        "2,4,0\r\n"
        "3,6,1\r\n"
        "4,8,1\r\n"
        "5,10,1\r\n");
    auto loaded = Dataset::loadCsv(csv, 1);
    assert(loaded && loaded->size() == 5);
    assert(loaded->featureCount() == 2 && loaded->targetCount() == 1);
    assert(loaded->featureNames().size() == 2);
    assert(loaded->featureNames()[0] == "length");

    Dataset dataset;
    assert(dataset.addSample({0.0, 0.0}, {0.0}));
    assert(dataset.addSample({1.0, 2.0}, {1.0}));
    assert(!dataset.addSample({1.0}, {0.0}));
    assert(!dataset.addSample({std::numeric_limits<double>::infinity()}, {0.0}));

    NeuralNetwork network({2, 4, 1}, Activation::Tanh, Activation::Sigmoid, 17);
    TrainerOptions options;
    options.network.epochs = 500;
    options.network.learningRate = 0.05;
    options.validationFraction = 0.2;
    auto report = Trainer::train(network, *loaded, options);
    assert(report);
    assert(report->trainingSamples == 4 && report->validationSamples == 1);
    assert(std::isfinite(report->trainingMse));
    assert(std::isfinite(report->validationMse));

    NeuralNetwork wrongShape({1, 1});
    assert(!Trainer::train(wrongShape, *loaded, options));

    std::istringstream malformed("a,b,label\n1,not-a-number,0\n");
    assert(!Dataset::loadCsv(malformed, 1));

    std::istringstream malformedQuotes("a,b,label\n\"unterminated,2,0\n");
    assert(!Dataset::loadCsv(malformedQuotes, 1));

    std::istringstream noHeader("1,2,0\n3,4,1\n");
    auto raw = Dataset::loadCsv(noHeader, 1, false);
    assert(raw && raw->size() == 2 && raw->featureNames().empty());

    TrainerOptions noValidation;
    noValidation.validationFraction = 0.0;
    noValidation.network.epochs = 2;
    auto noValidationReport = Trainer::train(network, *loaded, noValidation);
    assert(noValidationReport && noValidationReport->validationSamples == 0);
}
