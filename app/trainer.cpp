#include "ai/neural/NeuralNetwork.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <utility>

namespace {
using lulz::ai::neural::Activation;
using lulz::ai::neural::NeuralNetwork;
using lulz::ai::neural::TrainingOptions;

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

struct Sample {
    std::vector<double> features;
    double label = 0.0;
};
struct Metrics {
    std::size_t tn = 0, fp = 0, fn = 0, tp = 0;
    double accuracy() const {
        const auto total = tn + fp + fn + tp;
        return total ? static_cast<double>(tn + tp) / total : 0.0;
    }
    double precision() const {
        return tp + fp ? static_cast<double>(tp) / (tp + fp) : 0.0;
    }
    double recall() const {
        return tp + fn ? static_cast<double>(tp) / (tp + fn) : 0.0;
    }
    double f1() const {
        const double p = precision(), r = recall();
        return p + r > 0.0 ? 2.0 * p * r / (p + r) : 0.0;
    }
};

bool parseNumber(const std::string& text, double& value) {
    try {
        std::size_t used = 0;
        value = std::stod(text, &used);
        return used == text.size() && std::isfinite(value);
    } catch (...) { return false; }
}

bool loadDataset(const std::string& path, std::vector<Sample>& samples, std::string& error) {
    std::ifstream input(path);
    if (!input) { error = "Cannot open dataset: " + path; return false; }
    std::string line;
    if (!std::getline(input, line)) { error = "Dataset is empty"; return false; }
    std::vector<std::string> expected{"label"};
    expected.insert(expected.end(), kFeatureNames.begin(), kFeatureNames.end());
    std::stringstream header(line);
    std::string cell;
    for (const auto& name : expected) {
        if (!std::getline(header, cell, ',') || cell != name) {
            error = "CSV header mismatch. Expected columns: label followed by the 28 numeric feature names in the documented order.";
            return false;
        }
    }
    if (std::getline(header, cell, ',')) { error = "CSV contains unexpected extra columns"; return false; }

    std::size_t lineNumber = 1;
    while (std::getline(input, line)) {
        ++lineNumber;
        if (line.empty()) continue;
        std::stringstream row(line);
        if (!std::getline(row, cell, ',')) { error = "Missing label at line " + std::to_string(lineNumber); return false; }
        Sample sample;
        if (cell == "benign") sample.label = 0.0;
        else if (cell == "malicious") sample.label = 1.0;
        else { error = "Label must be benign or malicious at line " + std::to_string(lineNumber); return false; }
        for (std::size_t i = 0; i < kFeatureNames.size(); ++i) {
            if (!std::getline(row, cell, ',')) { error = "Missing feature at line " + std::to_string(lineNumber); return false; }
            double value = 0.0;
            if (!parseNumber(cell, value)) { error = "Invalid numeric feature at line " + std::to_string(lineNumber); return false; }
            sample.features.push_back(value);
        }
        if (std::getline(row, cell, ',')) { error = "Unexpected extra value at line " + std::to_string(lineNumber); return false; }
        samples.push_back(std::move(sample));
    }
    if (samples.size() < 20) { error = "At least 20 labeled samples are required"; return false; }
    const auto benign = std::count_if(samples.begin(), samples.end(), [](const Sample& s) { return s.label == 0.0; });
    if (benign < 7 || samples.size() - benign < 7) {
        error = "Dataset must contain at least seven benign and seven malicious samples for stratified train/validation/test splits";
        return false;
    }
    return true;
}

std::vector<double> predictInput(const Sample& sample, const std::vector<double>& means,
                                 const std::vector<double>& scales) {
    std::vector<double> result(sample.features.size());
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = (sample.features[i] - means[i]) / scales[i];
    return result;
}

Metrics evaluate(const NeuralNetwork& model, const std::vector<Sample>& samples,
                 const std::vector<double>& means, const std::vector<double>& scales) {
    Metrics metrics;
    for (const auto& sample : samples) {
        const auto prediction = model.predict(predictInput(sample, means, scales));
        if (!prediction || prediction->empty()) continue;
        const bool positive = prediction->front() >= 0.5;
        if (sample.label == 1.0) positive ? ++metrics.tp : ++metrics.fn;
        else positive ? ++metrics.fp : ++metrics.tn;
    }
    return metrics;
}

void printMetrics(const char* name, const Metrics& m) {
    std::cout << name << " metrics\n"
              << "  accuracy : " << m.accuracy() << "\n"
              << "  precision: " << m.precision() << "\n"
              << "  recall   : " << m.recall() << "\n"
              << "  F1       : " << m.f1() << "\n"
              << "  confusion matrix (actual rows: benign, malicious; predicted columns: benign, malicious)\n"
              << "             benign  malicious\n"
              << "  benign       " << m.tn << "       " << m.fp << "\n"
              << "  malicious    " << m.fn << "       " << m.tp << "\n";
}
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: lulz_trainer <dataset.csv> <output.lznn>\n";
        return 2;
    }

    std::vector<Sample> samples;
    std::string error;
    if (!loadDataset(argv[1], samples, error)) {
        std::cerr << "Dataset error: " << error << '\n';
        return 2;
    }

    std::mt19937 rng(0x4c554c5a);
    std::vector<Sample> benign, malicious;
    for (const auto& sample : samples)
        (sample.label == 0.0 ? benign : malicious).push_back(sample);
    std::shuffle(benign.begin(), benign.end(), rng);
    std::shuffle(malicious.begin(), malicious.end(), rng);

    std::vector<Sample> training, validation, testing;
    const auto splitClass = [&](const std::vector<Sample>& group) {
        const std::size_t trainEnd = group.size() * 70 / 100;
        const std::size_t validationEnd = trainEnd + group.size() * 15 / 100;
        training.insert(training.end(), group.begin(), group.begin() + static_cast<std::ptrdiff_t>(trainEnd));
        validation.insert(validation.end(), group.begin() + static_cast<std::ptrdiff_t>(trainEnd),
                          group.begin() + static_cast<std::ptrdiff_t>(validationEnd));
        testing.insert(testing.end(), group.begin() + static_cast<std::ptrdiff_t>(validationEnd), group.end());
    };
    splitClass(benign);
    splitClass(malicious);
    std::shuffle(training.begin(), training.end(), rng);
    std::shuffle(validation.begin(), validation.end(), rng);
    std::shuffle(testing.begin(), testing.end(), rng);

    std::vector<double> means(kFeatureNames.size(), 0.0), scales(kFeatureNames.size(), 1.0);
    for (const auto& sample : training)
        for (std::size_t i = 0; i < means.size(); ++i) means[i] += sample.features[i];
    for (double& mean : means) mean /= static_cast<double>(training.size());
    for (const auto& sample : training)
        for (std::size_t i = 0; i < scales.size(); ++i) {
            const double delta = sample.features[i] - means[i];
            scales[i] += delta * delta;
        }
    for (double& scale : scales) {
        scale = std::sqrt((scale - 1.0) / static_cast<double>(training.size()));
        if (scale < 1.0e-9) scale = 1.0;
    }

    std::vector<std::vector<double>> inputs, targets;
    inputs.reserve(training.size()); targets.reserve(training.size());
    for (const auto& sample : training) {
        inputs.push_back(predictInput(sample, means, scales));
        targets.push_back({sample.label});
    }

    NeuralNetwork model({kFeatureNames.size(), 32, 16, 1},
                        Activation::Relu, Activation::Sigmoid, 0x4c554c5a);
    TrainingOptions options;
    options.epochs = 300;
    options.learningRate = 0.005;
    options.momentum = 0.85;
    options.weightDecay = 0.0001;
    options.gradientClipNorm = 5.0;
    options.seed = 0x4c554c5a;
    const auto report = model.train(inputs, targets, options, &error);
    if (!report) { std::cerr << "Training failed: " << error << '\n'; return 2; }

    const std::string modelPath = argv[2];
    {
        std::ofstream output(modelPath, std::ios::binary);
        if (!output || !model.save(output, &error)) {
            std::cerr << "Cannot save model: " << (error.empty() ? modelPath : error) << '\n';
            return 2;
        }
    }
    {
        std::ofstream output(modelPath + ".norm");
        if (!output) { std::cerr << "Cannot save normalization metadata\n"; return 2; }
        output << "LULZNORM1\n" << kFeatureNames.size() << '\n' << std::setprecision(17);
        for (std::size_t i = 0; i < kFeatureNames.size(); ++i)
            output << kFeatureNames[i] << ',' << means[i] << ',' << scales[i] << '\n';
        if (!output) { std::cerr << "Failed writing normalization metadata\n"; return 2; }
    }

    std::cout << std::fixed << std::setprecision(4)
              << "LULZ AI TRAINING COMPLETE\n"
              << "Samples: " << samples.size() << " (train " << training.size()
              << ", validation " << validation.size() << ", test " << testing.size() << ")\n"
              << "Features: " << kFeatureNames.size() << "\n"
              << "Epochs: " << report->epochsCompleted << "\n"
              << "Training loss: " << report->initialLoss << " -> " << report->finalLoss << "\n"
              << "Model: " << modelPath << "\n"
              << "Normalizer: " << modelPath << ".norm\n"
              << "Note: the validation and test metrics below are evaluation only; the test set is not used for training.\n";
    printMetrics("Validation", evaluate(model, validation, means, scales));
    printMetrics("Test", evaluate(model, testing, means, scales));
    std::cout << "Dataset split is shuffled with a fixed seed; verify class balance and dataset provenance before trusting metrics.\n";
    return 0;
}
