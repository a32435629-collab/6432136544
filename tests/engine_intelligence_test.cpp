#include "lulz/engine/GameEngineIntelligence.hpp"

#include <array>
#include <cassert>

int main() {
    using lulz::ImportSymbol;
    const std::array imports{
        ImportSymbol{"d3d12.dll", "D3D12CreateDevice"},
        ImportSymbol{"dxgi.dll", "CreateDXGIFactory2"},
        ImportSymbol{"KERNEL32.dll", "LoadLibraryW"},
        ImportSymbol{"KERNEL32.dll", "GetProcAddress"},
        ImportSymbol{"XAudio2_9.dll", "XAudio2Create"},
        ImportSymbol{"ws2_32.dll", "socket"},
        ImportSymbol{"KERNEL32.dll", "CreateThread"}
    };
    const auto report = lulz::engine::analyzeEngineImports(imports, 1);
    assert(report.importCount == 6);
    assert(report.delayImportCount == 1);
    assert(report.supportsDynamicLoading);
    assert(report.importedModules.size() == 5);
    bool d3d12 = false, dxgi = false, audio = false, network = false, threading = false;
    for (const auto& signal : report.signals) {
        d3d12 |= signal.name == "Direct3D 12";
        dxgi |= signal.name == "DXGI";
        audio |= signal.subsystem == "audio";
        network |= signal.subsystem == "network";
        threading |= signal.subsystem == "concurrency";
    }
    assert(d3d12 && dxgi && audio && network && threading);
    const auto json = lulz::engine::engineReportToJson(report);
    assert(json.find("lulz.game-engine-intelligence.v1") != std::string::npos);
    assert(json.find("Direct3D 12") != std::string::npos);
    return 0;
}
