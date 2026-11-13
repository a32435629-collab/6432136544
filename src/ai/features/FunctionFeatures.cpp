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
    std::size_t decodedFunctions = 0;
    std::size_t functionsWithNoDecodedInstructions = 0;

    for (const auto& function : context.functions) {
        if (!function.hasDecodedInstructions) {
            continue;
        }

        ++decodedFunctions;
        const std::size_t count = function.assembly.size();
        totalInstructions += count;
        maxFunctionSize = std::max(maxFunctionSize, count);

        if (count == 0) {
            ++functionsWithNoDecodedInstructions;
        }
    }

    output.addNumeric(
        "functions.average_size",
        decodedFunctions == 0
            ? 0.0
            : static_cast<double>(totalInstructions) /
              static_cast<double>(decodedFunctions)
    );

    output.addNumeric(
        "functions.max_size",
        static_cast<double>(maxFunctionSize)
    );

    output.addNumeric(
        "functions.with_no_decoded_instructions",
        static_cast<double>(functionsWithNoDecodedInstructions)
    );
}

} // namespace lulz::ai::features