#include "AnalysisReport.hpp"

#include <iomanip>
#include <sstream>

namespace lulz::ai::analysis {
std::string AnalysisReport::toText(const AnalysisResult& result) {
    std::ostringstream output;
    output << "================================\n";
    output << " DLL_LULZ_AI ANALYSIS REPORT\n";
    output << "================================\n\n";
    output << "Source: " << result.sourceLabel << '\n';
    output << "Status: " << (result.success ? "SUCCESS" : "FAILED") << "\n\n";
    if (!result.error.empty()) output << "ERROR\n" << result.error << "\n\n";
    output << "SUMMARY\n" << (result.summary.empty() ? "No summary available." : result.summary) << "\n\n";
    output << "FEATURES (" << result.features.size() << ")\n";
    for (const auto& feature : result.features.values) {
        output << "- " << feature.name << ": ";
        if (feature.type == features::FeatureType::Categorical) output << feature.textValue;
        else output << std::setprecision(6) << feature.value;
        output << '\n';
    }
    output << "\nFINDINGS\n";
    if (result.findings.empty()) output << "No findings.\n";
    else for (std::size_t i = 0; i < result.findings.size(); ++i)
        output << (i + 1) << ". " << result.findings[i] << '\n';
    output << "\n================================\n";
    return output.str();
}
} // namespace lulz::ai::analysis
