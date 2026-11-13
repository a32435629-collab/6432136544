#include "InstructionFeatures.hpp"

#include <string>

namespace lulz::ai::features {

void InstructionFeatures::extract(
    const AIContext& context,
    FeatureVector& output
) {
    std::size_t calls = 0;
    std::size_t jumps = 0;
    std::size_t stackOperations = 0;
    std::size_t returns = 0;

    for (const auto& function : context.functions) {
        for (const auto& instruction : function.assembly) {
            if (instruction.find("call") != std::string::npos) {
                ++calls;
            }

            if (instruction.find("jmp") != std::string::npos ||
                instruction.find("jump") != std::string::npos) {
                ++jumps;
            }

            if (instruction.find("Stack allocation") != std::string::npos) {
                ++stackOperations;
            }

            if (instruction.find("ret") != std::string::npos) {
                ++returns;
            }
        }
    }

    output.addNumeric("instructions.calls", calls);
    output.addNumeric("instructions.jumps", jumps);
    output.addNumeric("instructions.stack_operations", stackOperations);
    output.addNumeric("instructions.returns", returns);
}

} // namespace lulz::ai::features