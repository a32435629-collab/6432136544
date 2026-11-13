#include "AnalysisReport.hpp"

#include <sstream>

namespace lulz::ai::analysis {

std::string AnalysisReport::toText(
    const AnalysisResult& result
) {
    std::ostringstream output;

    output << "================================\n";
    output << " DLL_LULZ_AI ANALYSIS REPORT\n";
    output << "================================\n\n";

    output << "Source: " << result.sourceLabel << '\n';
    output << "Status: "
           << (result.success ? "SUCCESS" : "FAILED")
           << "\n\n";

    if (!result.error.empty()) {
        output << "ERROR\n";
        output << result.error << "\n\n";
    }

    output << "SUMMARY\n";
    output << (result.summary.empty()
        ? "No summary available."
        : result.summary);
    output << "\n\n";

    output << "FINDINGS\n";

    if (result.findings.empty()) {
        output << "No findings.\n";
    } else {
        for (std::size_t i = 0;
             i < result.findings.size();
             ++i) {
            output << (i + 1) << ". "
                   << result.findings[i] << '\n';
        }
    }

    output << "\n================================\n";

    return output.str();
}

} // namespace lulz::ai::analysis