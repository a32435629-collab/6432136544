#pragma once

#include <string>

namespace lulz::ai::features {

enum class FeatureType {
    Numeric,
    Categorical,
    Boolean
};

struct Feature {
    std::string name;
    FeatureType type = FeatureType::Numeric;
    double value = 0.0;
    std::string textValue;
};

} // namespace lulz::ai::features