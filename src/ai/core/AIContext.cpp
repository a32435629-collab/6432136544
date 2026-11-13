
#include "AIContext.hpp"

namespace lulz::ai {

bool AIContext::validate(std::string* error) const {
    if (filePath.empty()) {
        if (error) *error = "File path is empty";
        return false;
    }

    if (format.empty()) {
        if (error) *error = "File format is empty";
        return false;
    }

    if (architecture.empty()) {
        if (error) *error = "Architecture is empty";
        return false;
    }

    if (functions.size() > 100000) {
        if (error) *error = "Too many functions";
        return false;
    }

    if (imports.size() > 500000) {
        if (error) *error = "Too many imports";
        return false;
    }

    if (error) error->clear();
    return true;
}

std::size_t AIContext::instructionCount() const {
    std::size_t total = 0;

    for (const auto& function : functions) {
        if (!function.hasDecodedInstructions) {
            continue;
        }

        total += function.assembly.size();
    }

    return total;
}

} // namespace lulz::ai
