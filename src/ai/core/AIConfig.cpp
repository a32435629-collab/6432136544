
#include "AIConfig.hpp"

namespace lulz::ai {

bool AIConfig::validate(std::string* error) const {
    if (maxFunctions == 0 || maxFunctions > 100000) {
        if (error) *error = "Invalid maxFunctions value";
        return false;
    }

    if (maxImports == 0 || maxImports > 500000) {
        if (error) *error = "Invalid maxImports value";
        return false;
    }

    if (maxInstructions == 0 || maxInstructions > 10000000) {
        if (error) *error = "Invalid maxInstructions value";
        return false;
    }

    if (provider != AIProvider::None && modelName.empty()) {
        if (error) *error = "Model name is required";
        return false;
    }

    if (error) error->clear();
    return true;
}

} // namespace lulz::ai
