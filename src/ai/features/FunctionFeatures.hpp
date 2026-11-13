#pragma once

#include "FeatureVector.hpp"
#include "ai/core/AIContext.hpp"

namespace lulz::ai::features {

class FunctionFeatures {
public:
    static void extract(
        const AIContext& context,
        FeatureVector& output
    );
};

} // namespace lulz::ai::features