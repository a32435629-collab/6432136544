#include "FunctionFeatures.hpp"

#include <algorithm>
#include <cstddef>

namespace lulz::ai::features {

void FunctionFeatures::extract(
    const AIContext& context,
    FeatureVector& output
) {
    std::size_t totalInstructions = 0;
    std::size_t maxFunctionSize = 0;
    std::size_t emptyFunctions = 0;

    for (const auto& function : context.functions) {
        const std::size_t count = function.assembly.size();

        totalInstructions += count;
        maxFunctionSize = std::max(maxFunctionSize, count);

        if (count == 0) {
            ++emptyFunctions;
        }
    }

    output.addNumeric(
        "functions.average_size",
        context.functions.empty()
            ? 0.0
            : static_cast<double>(totalInstructions) /
              static_cast<double>(context.functions.size())
    );

    output.addNumeric(
        "functions.max_size",
        static_cast<double>(maxFunctionSize)
    );

    output.addNumeric(
        "functions.empty",
        static_cast<double>(emptyFunctions)
    );
}

} // namespace lulz::ai::features