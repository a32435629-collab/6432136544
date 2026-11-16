#include "ai/builder/BuilderLearning.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3 || argc > 5) {
        std::cerr << "LULZ Builder Trainer\n"
                  << "Usage: lulz_builder_trainer <dataset.json> <model-directory> [--epochs N]\n";
        return 2;
    }
    lulz::ai::builder::BuilderTrainingOptions options;
    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--epochs" && i + 1 < argc) {
            try { options.network.epochs = static_cast<std::size_t>(std::stoull(argv[++i])); }
            catch (...) { std::cerr << "Invalid epoch count\n"; return 2; }
        } else {
            std::cerr << "Unknown or incomplete option: " << arg << '\n';
            return 2;
        }
    }
    std::string error;
    const auto report = lulz::ai::builder::BuilderLearning::trainDataset(
        argv[1], argv[2], options, &error);
    if (!report) { std::cerr << "Training failed: " << error << '\n'; return 1; }
    std::cout << "Builder training complete\n"
              << "Examples: " << report->examples << '\n'
              << "Assembly loss: " << report->assembly.initialLoss << " -> " << report->assembly.finalLoss << '\n'
              << "Repair loss: " << report->repair.initialLoss << " -> " << report->repair.finalLoss << '\n'
              << "Models: " << (std::filesystem::path(argv[2]) / "builder_assembly.lzb").string()
              << " and " << (std::filesystem::path(argv[2]) / "builder_repair.lzb").string() << '\n';
    return 0;
}
