#include "InstructionFeatures.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace lulz::ai::features {
namespace {
std::string lowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}
std::string mnemonicOf(const std::string& text) {
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    const auto last = text.find_first_of(" \t", first);
    return lowerAscii(text.substr(first, last == std::string::npos ? last : last - first));
}
bool isJump(std::string_view mnemonic) {
    return mnemonic.size() >= 2 && mnemonic[0] == 'j';
}
bool isStackOperation(std::string_view mnemonic, const std::string& instruction) {
    return mnemonic == "push" || mnemonic == "pushf" || mnemonic == "pushfq" ||
           mnemonic == "pop" || mnemonic == "popf" || mnemonic == "popfq" ||
           mnemonic == "enter" || mnemonic == "leave" ||
           (mnemonic == "sub" && instruction.find("rsp") != std::string::npos) ||
           (mnemonic == "add" && instruction.find("rsp") != std::string::npos);
}
} // namespace

void InstructionFeatures::extract(const AIContext& context, FeatureVector& output) {
    std::size_t decodedFunctions=0, decodedInstructions=0, calls=0, jumps=0;
    std::size_t stackOperations=0, returns=0, invalidText=0;
    for (const auto& function : context.functions) {
        if (!function.hasDecodedInstructions) continue;
        ++decodedFunctions;
        for (const auto& rawText : function.assembly) {
            ++decodedInstructions;
            const std::string instruction=lowerAscii(rawText);
            const std::string mnemonic=mnemonicOf(rawText);
            if (mnemonic.empty()) { ++invalidText; continue; }
            if (mnemonic=="call" || mnemonic=="callq") ++calls;
            if (isJump(mnemonic)) ++jumps;
            if (isStackOperation(mnemonic,instruction)) ++stackOperations;
            if (mnemonic=="ret" || mnemonic=="retf" || mnemonic=="retn" ||
                mnemonic=="iret" || mnemonic=="iretq") ++returns;
        }
    }
    output.addNumeric("instructions.decoded_functions",static_cast<double>(decodedFunctions));
    output.addNumeric("instructions.total",static_cast<double>(decodedInstructions));
    output.addNumeric("instructions.calls",static_cast<double>(calls));
    output.addNumeric("instructions.jumps",static_cast<double>(jumps));
    output.addNumeric("instructions.stack_operations",static_cast<double>(stackOperations));
    output.addNumeric("instructions.returns",static_cast<double>(returns));
    output.addNumeric("instructions.unparsed_text",static_cast<double>(invalidText));
    output.addNumeric("instructions.control_flow",static_cast<double>(calls+jumps+returns));
}
} // namespace lulz::ai::features
