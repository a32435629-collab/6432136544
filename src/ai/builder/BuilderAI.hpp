#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace lulz::ai::builder {

struct BuilderOptions {
    std::filesystem::path outputDirectory = "dist";
    bool overwrite = false;
    std::size_t maximumFiles = 2048;
    std::size_t maximumFileBytes = 8 * 1024 * 1024;
    std::size_t maximumTotalBytes = 64 * 1024 * 1024;
};

struct BuildReport {
    bool success = false;
    std::string projectName;
    std::filesystem::path projectDirectory;
    std::vector<std::filesystem::path> createdFiles;
    std::string error;
};

class BuilderAI {
public:
    BuildReport buildFromJsonFile(
        const std::filesystem::path& jsonFile,
        const BuilderOptions& options = {}
    ) const;

    BuildReport buildFromJson(
        const std::string& json,
        const BuilderOptions& options = {}
    ) const;
};

} // namespace lulz::ai::builder
