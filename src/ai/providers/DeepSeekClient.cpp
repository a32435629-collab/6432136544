#include "DeepSeekClient.hpp"
#include "OpenAIClient.hpp"

namespace lulz::ai::providers {
bool analyzeWithDeepSeek(
    const std::string& endpoint,
    const std::string& apiKey,
    const std::string& model,
    const std::string& prompt,
    std::string& response,
    std::string* error
) {
    const std::string target = endpoint.empty()
        ? "https://api.deepseek.com/chat/completions"
        : endpoint;
    if (!analyzeWithOpenAI(target, apiKey, model, prompt, response, error)) {
        if (error && error->find("OpenAI") != std::string::npos)
            *error = "DeepSeek: " + *error;
        return false;
    }
    return true;
}
} // namespace lulz::ai::providers
