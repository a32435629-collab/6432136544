#pragma once

#include "Feature.hpp"

#include <string>
#include <vector>

namespace lulz::ai::features {

struct FeatureVector {
    std::vector<Feature> values;

    void addNumeric(const std::string& name, double value) {
        values.push_back({
            name,
            FeatureType::Numeric,
            value,
            {}
        });
    }

    void addBoolean(const std::string& name, bool value) {
        values.push_back({
            name,
            FeatureType::Boolean,
            value ? 1.0 : 0.0,
            {}
        });
    }

    void addCategorical(
        const std::string& name,
        const std::string& value
    ) {
        values.push_back({
            name,
            FeatureType::Categorical,
            0.0,
            value
        });
    }

    std::size_t size() const {
        return values.size();
    }

    bool empty() const {
        return values.empty();
    }
};

} // namespace lulz::ai::features