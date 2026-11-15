#include "ai/builder/BuilderAI.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 5) {
        std::cerr
            << "LULZ Builder AI 0.8.0\n"
            << "Usage: lulz_builder <project.json> [--out directory] [--force]\n";
        return 2;
    }

    lulz::ai::builder::BuilderOptions options;
    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--force") {
            options.overwrite = true;
        } else if (argument == "--out" && i + 1 < argc) {
            options.outputDirectory = argv[++i];
        } else {
            std::cerr << "Unknown or incomplete option: " << argument << '\n';
            return 2;
        }
    }

    const auto report =
        lulz::ai::builder::BuilderAI{}.buildFromJsonFile(argv[1], options);

    if (!report.success) {
        std::cerr << "Builder AI failed: " << report.error << '\n';
        return 1;
    }

    std::cout << "Builder AI 0.8.0\n"
              << "Project: " << report.projectName << '\n'
              << "Output: " << report.projectDirectory.string() << '\n'
              << "Files created: " << report.createdFiles.size() << '\n';
    for (const auto& path : report.createdFiles)
        std::cout << "  + " << path.string() << '\n';
    return 0;
}
