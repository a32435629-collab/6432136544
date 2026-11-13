#pragma once

#include "FeatureVector.hpp"
#include "ai/core/AIContext.hpp"

namespace lulz::ai::features {

class ImportFeatures {
public:
    static void extract(
        const AIContext& context,
        FeatureVector& output
    );
};

} // namespace lulz::ai::features