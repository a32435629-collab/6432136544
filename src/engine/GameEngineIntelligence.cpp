#include "lulz/engine/GameEngineIntelligence.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <string_view>

namespace lulz::engine {
namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool contains(std::string_view value, std::string_view token) {
    return value.find(token) != std::string_view::npos;
}

void add(EngineReport& report, const std::string& subsystem,
         const std::string& name, const std::string& evidence,
         double confidence = 0.95) {
    const auto duplicate = std::find_if(report.signals.begin(), report.signals.end(),
        [&](const EngineSignal& item) {
            return item.subsystem == subsystem && item.name == name;
        });
    if (duplicate == report.signals.end())
        report.signals.push_back({subsystem, name, evidence, confidence});
}

std::string escapeJson(const std::string& value) {
    std::string out;
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: if (ch >= 0x20) out.push_back(static_cast<char>(ch)); break;
        }
    }
    return out;
}

} // namespace

EngineReport analyzeEngineImports(std::span<const ImportSymbol> imports,
                                  std::size_t delayImportCount) {
    EngineReport report;
    report.importCount = imports.size() - std::min(imports.size(), delayImportCount);
    report.delayImportCount = delayImportCount;

    std::set<std::string> modules;
    for (const auto& item : imports) {
        const std::string module = lower(item.module);
        const std::string symbol = lower(item.name);
        modules.insert(item.module);

        if (symbol == "loadlibrarya" || symbol == "loadlibraryw" ||
            symbol == "loadlibraryexa" || symbol == "loadlibraryexw" ||
            symbol == "getprocaddress") {
            report.supportsDynamicLoading = true;
        }

        if (contains(module, "d3d12") || symbol == "d3d12createdevice")
            add(report, "graphics", "Direct3D 12", item.module + "!" + item.name);
        if (contains(module, "d3d11") || symbol == "d3d11createdevice")
            add(report, "graphics", "Direct3D 11", item.module + "!" + item.name);
        if (contains(module, "d3d10") || symbol == "d3d10createdevice")
            add(report, "graphics", "Direct3D 10", item.module + "!" + item.name);
        if (contains(module, "dxgi") || symbol == "createdxgifactory" ||
            symbol == "createdxgifactory1" || symbol == "createdxgifactory2")
            add(report, "graphics", "DXGI", item.module + "!" + item.name);
        if (contains(module, "vulkan") || symbol == "vkgetinstanceprocaddr")
            add(report, "graphics", "Vulkan", item.module + "!" + item.name);
        if (module == "opengl32.dll" || contains(symbol, "wglcreatecontext") ||
            symbol == "glgetstring")
            add(report, "graphics", "OpenGL", item.module + "!" + item.name);

        if (contains(module, "d3dcompiler") || module == "dxcompiler.dll" ||
            contains(module, "dxil"))
            add(report, "rendering", "Shader compiler/toolchain", item.module + "!" + item.name);
        if (contains(module, "xaudio") || module == "dsound.dll" ||
            module == "openal32.dll" || symbol == "waveoutwrite")
            add(report, "audio", "Audio API", item.module + "!" + item.name);
        if (module == "xinput1_4.dll" || module == "xinput9_1_0.dll" ||
            module == "dinput8.dll" || symbol == "getasynckeystate" ||
            symbol == "getrawinputdata")
            add(report, "input", "Input API", item.module + "!" + item.name);
        if (module == "winhttp.dll" || module == "wininet.dll" ||
            module == "ws2_32.dll" || contains(module, "curl"))
            add(report, "network", "Networking API", item.module + "!" + item.name);

        if (contains(module, "physx") || contains(module, "havok") ||
            contains(module, "bullet") || contains(module, "jolt") ||
            contains(module, "ode.dll"))
            add(report, "physics", "Physics middleware", item.module);
        if (symbol == "createthread" || symbol == "createthreadpool" ||
            symbol == "submitthreadpoolwork" || symbol == "initializecriticalsection" ||
            symbol == "srwlockexclusiveacquire" || symbol == "waitonaddress")
            add(report, "concurrency", "Threading and synchronization primitives",
                item.module + "!" + item.name, 0.90);
    }

    report.importedModules.assign(modules.begin(), modules.end());
    std::sort(report.signals.begin(), report.signals.end(),
        [](const EngineSignal& a, const EngineSignal& b) {
            if (a.subsystem != b.subsystem) return a.subsystem < b.subsystem;
            return a.name < b.name;
        });
    return report;
}

std::string engineReportToJson(const EngineReport& report) {
    std::ostringstream out;
    out << "{\n  \"schema\": \"lulz.game-engine-intelligence.v1\","
        << "\n  \"importCount\": " << report.importCount
        << ",\n  \"delayImportCount\": " << report.delayImportCount
        << ",\n  \"supportsDynamicLoading\": "
        << (report.supportsDynamicLoading ? "true" : "false")
        << ",\n  \"importedModules\": [";
    for (std::size_t i = 0; i < report.importedModules.size(); ++i) {
        if (i) out << ",";
        out << "\n    \"" << escapeJson(report.importedModules[i]) << "\"";
    }
    out << "\n  ],\n  \"signals\": [";
    for (std::size_t i = 0; i < report.signals.size(); ++i) {
        const auto& signal = report.signals[i];
        if (i) out << ",";
        out << "\n    {\"subsystem\": \"" << escapeJson(signal.subsystem)
            << "\", \"name\": \"" << escapeJson(signal.name)
            << "\", \"evidence\": \"" << escapeJson(signal.evidence)
            << "\", \"confidence\": " << std::fixed << std::setprecision(2)
            << signal.confidence << "}";
    }
    out << "\n  ],\n  \"limitations\": ["
        << "\"Import-table evidence only; dynamically loaded APIs and other process modules may be absent.\","
        << "\"No performance bottleneck or runtime renderer behavior is inferred.\""
        << "]\n}\n";
    return out.str();
}

} // namespace lulz::engine
