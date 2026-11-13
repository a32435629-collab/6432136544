#include "FeatureExtractor.hpp"

#include "ImportFeatures.hpp"
#include "FunctionFeatures.hpp"
#include "InstructionFeatures.hpp"

namespace lulz::ai::features {

FeatureVector FeatureExtractor::extract(
    const AIContext& context
) const {
    FeatureVector result;

    result.addNumeric(
        "imports.total",
        static_cast<double>(context.imports.size())
    );

    result.addNumeric(
        "functions.total",
        static_cast<double>(context.functions.size())
    );

    result.addCategorical(
        "binary.format",
        context.format
    );

    result.addCategorical(
        "binary.architecture",
        context.architecture
    );

    ImportFeatures::extract(context, result);
    FunctionFeatures::extract(context, result);
    InstructionFeatures::extract(context, result);

    return result;
}

} // namespace lulz::ai::features