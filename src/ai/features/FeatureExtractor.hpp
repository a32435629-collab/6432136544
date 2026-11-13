#pragma once

#include "FeatureVector.hpp"
#include "ai/core/AIContext.hpp"

namespace lulz::ai::features {

class FeatureExtractor {
public:
    FeatureVector extract(const AIContext& context) const;
};

} // namespace lulz::ai::features