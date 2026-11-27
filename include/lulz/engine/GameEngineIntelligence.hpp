#pragma once

#include "lulz/formats/pe/PEParser.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace lulz::engine {

struct EngineSignal {
    std::string subsystem;
    std::string name;
    std::string evidence;
    double confidence = 0.0;
};

struct EngineReport {
    std::vector<EngineSignal> signals;
    std::vector<std::string> importedModules;
    std::size_t importCount = 0;
    std::size_t delayImportCount = 0;
    bool supportsDynamicLoading = false;
};

// Classifies only explicit import-table evidence. It does not scan packed or
// protected sections and does not infer runtime use from a missing import.
EngineReport analyzeEngineImports(
    std::span<const ImportSymbol> imports,
    std::size_t delayImportCount = 0
);

std::string engineReportToJson(const EngineReport& report);

} // namespace lulz::engine
