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
bool isJump(std::string_view m) {
    return m == "jmp" || m == "ljmp" || (m.size() >= 2 && m[0] == 'j') ||
           m.starts_with("loop") || m.starts_with("jcx");
}
bool isStackOperation(std::string_view m, const std::string& line) {
    return m == "push" || m.starts_with("pushf") || m == "pop" ||
           m.starts_with("popf") || m == "enter" || m == "leave" ||
           ((m == "sub" || m == "add" || m == "lea") &&
            (line.find("rsp") != std::string::npos || line.find("esp") != std::string::npos));
}
}
void InstructionFeatures::extract(const AIContext& context, FeatureVector& output) {
    std::size_t decodedFunctions=0, decodedInstructions=0, calls=0, jumps=0;
    std::size_t stackOperations=0, returns=0, invalidText=0;
    for (const auto& function : context.functions) {
        if (!function.hasDecodedInstructions) continue;
        ++decodedFunctions;
        const auto& lines = function.decodedInstructions.empty()
            ? function.assembly : function.decodedInstructions;
        for (const auto& raw : lines) {
            ++decodedInstructions;
            const std::string instruction=lowerAscii(raw);
            const std::string mnemonic=mnemonicOf(raw);
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
