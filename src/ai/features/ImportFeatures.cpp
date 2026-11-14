#include "ImportFeatures.hpp"

#include <cctype>
#include <initializer_list>
#include <string>

namespace lulz::ai::features {
namespace {
std::string lowerAscii(const std::string& value) {
    std::string result = value;
    for (char& ch : result) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return result;
}
bool containsAny(const std::string& value, std::initializer_list<const char*> needles) {
    for (const char* needle : needles) if (value.find(needle) != std::string::npos) return true;
    return false;
}
}
void ImportFeatures::extract(const AIContext& context, FeatureVector& output) {
    std::size_t dynamicResolution=0, memoryOperations=0, remoteMemory=0, network=0;
    std::size_t process=0, crypto=0, persistence=0, antiAnalysis=0;
    for (const auto& rawImport : context.imports) {
        const std::string name=lowerAscii(rawImport);
        if (containsAny(name, {"loadlibrary","getprocaddress","ldrloaddll","ldrgetprocedureaddress"})) ++dynamicResolution;
        if (containsAny(name, {"virtualalloc","virtualprotect","ntallocatevirtualmemory","ntprotectvirtualmemory"})) ++memoryOperations;
        if (containsAny(name, {"virtualallocex","virtualprotectex","writeprocessmemory","ntwritevirtualmemory"})) ++remoteMemory;
        if (containsAny(name, {"internet","http","winhttp","socket","connect","wsasend","recv"})) ++network;
        if (containsAny(name, {"createprocess","openprocess","ntopenprocess","createremotethread","ntcreatethread"})) ++process;
        if (containsAny(name, {"crypt","bcrypt","ncrypt","crypto"})) ++crypto;
        if (containsAny(name, {"regsetvalue","regcreatekey","createservice","startservice","taskschd"})) ++persistence;
        if (containsAny(name, {"isdebuggerpresent","checkremotedebuggerpresent","ntqueryinformationprocess","outputdebugstring","etweventwrite"})) ++antiAnalysis;
    }
    const double total=static_cast<double>(context.imports.size());
    const auto ratio=[&](const char* key,std::size_t count) {
        output.addNumeric(key,total==0.0?0.0:static_cast<double>(count)/total);
    };
    output.addNumeric("imports.dynamic_resolution",static_cast<double>(dynamicResolution));
    output.addNumeric("imports.memory_operations",static_cast<double>(memoryOperations));
    output.addNumeric("imports.remote_memory",static_cast<double>(remoteMemory));
    output.addNumeric("imports.network",static_cast<double>(network));
    output.addNumeric("imports.process",static_cast<double>(process));
    output.addNumeric("imports.crypto",static_cast<double>(crypto));
    output.addNumeric("imports.persistence",static_cast<double>(persistence));
    output.addNumeric("imports.anti_analysis",static_cast<double>(antiAnalysis));
    ratio("imports.remote_memory_ratio",remoteMemory);
    ratio("imports.network_ratio",network);
}
} // namespace lulz::ai::features
