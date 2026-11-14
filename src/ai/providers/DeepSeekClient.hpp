#pragma once
#include <string>

namespace lulz::ai::providers {
bool analyzeWithDeepSeek(
    const std::string& endpoint,
    const std::string& apiKey,
    const std::string& model,
    const std::string& prompt,
    std::string& response,
    std::string* error = nullptr
);
}
