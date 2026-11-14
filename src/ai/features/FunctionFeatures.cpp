#include "FunctionFeatures.hpp"
#include <algorithm>
#include <cstddef>

namespace lulz::ai::features {
void FunctionFeatures::extract(const AIContext& context, FeatureVector& output) {
    std::size_t totalInstructions=0, maxFunctionSize=0, minFunctionSize=0;
    std::size_t decodedFunctions=0, emptyDecodedFunctions=0;
    for (const auto& function : context.functions) {
        if (!function.hasDecodedInstructions) continue;
        const std::size_t count = function.decodedInstructions.empty()
            ? function.assembly.size() : function.decodedInstructions.size();
        if (decodedFunctions==0) minFunctionSize=count;
        else minFunctionSize=std::min(minFunctionSize,count);
        ++decodedFunctions;
        totalInstructions+=count;
        maxFunctionSize=std::max(maxFunctionSize,count);
        if (count==0) ++emptyDecodedFunctions;
    }
    const std::size_t unavailableFunctions=context.functions.size()-decodedFunctions;
    const double functionCount=static_cast<double>(context.functions.size());
    output.addNumeric("functions.decoded",static_cast<double>(decodedFunctions));
    output.addNumeric("functions.undecoded",static_cast<double>(unavailableFunctions));
    output.addNumeric("functions.decoded_ratio",functionCount==0.0?0.0:static_cast<double>(decodedFunctions)/functionCount);
    output.addNumeric("functions.average_size",decodedFunctions==0?0.0:static_cast<double>(totalInstructions)/static_cast<double>(decodedFunctions));
    output.addNumeric("functions.min_size",decodedFunctions==0?0.0:static_cast<double>(minFunctionSize));
    output.addNumeric("functions.max_size",static_cast<double>(maxFunctionSize));
    output.addNumeric("functions.empty_decoded",static_cast<double>(emptyDecodedFunctions));
}
} // namespace lulz::ai::features
