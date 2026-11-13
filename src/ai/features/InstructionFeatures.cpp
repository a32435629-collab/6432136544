#include "InstructionFeatures.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace lulz::ai::features {
namespace {

std::string lowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

} // namespace

void InstructionFeatures::extract(
    const AIContext& context,
    FeatureVector& output
) {
    std::size_t decodedFunctions = 0;
    std::size_t decodedInstructions = 0;
    std::size_t calls = 0;
    std::size_t jumps = 0;
    std::size_t stackOperations = 0;
    std::size_t returns = 0;

    for (const auto& function : context.functions) {
        if (!function.hasDecodedInstructions) {
            continue;
        }

        ++decodedFunctions;
        for (const auto& text : function.assembly) {
            ++decodedInstructions;
            const std::string instruction = lowerAscii(text);

            if (instruction.rfind("call", 0) == 0) ++calls;
            if (instruction.rfind("jmp", 0) == 0 ||
                instruction.rfind("j", 0) == 0) ++jumps;
            if (instruction.find("push") == 0 ||
                instruction.find("pop") == 0 ||
                instruction.find("sub rsp") == 0 ||
                instruction.find("add rsp") == 0) {
                ++stackOperations;
            }
            if (instruction.rfind("ret", 0) == 0) ++returns;
        }
    }

    output.addNumeric("instructions.decoded_functions", decodedFunctions);
    output.addNumeric("instructions.total", decodedInstructions);
    output.addNumeric("instructions.calls", calls);
    output.addNumeric("instructions.jumps", jumps);
    output.addNumeric("instructions.stack_operations", stackOperations);
    output.addNumeric("instructions.returns", returns);
}

} // namespace lulz::ai::features