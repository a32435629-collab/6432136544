#pragma once
#include <string>
#include <vector>
namespace lulz {
struct Finding {
    std::string category;
    std::string summary;
    double confidence{0.0};
};
struct AnalysisReport {
    std::string inputName;
    std::vector<Finding> findings;
};
}
