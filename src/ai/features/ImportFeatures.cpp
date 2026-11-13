#include "ImportFeatures.hpp"

namespace lulz::ai::features {

void ImportFeatures::extract(
    const AIContext& context,
    FeatureVector& output
) {
    std::size_t dllLoaders = 0;
    std::size_t memoryFunctions = 0;
    std::size_t networkFunctions = 0;
    std::size_t processFunctions = 0;
    std::size_t cryptoFunctions = 0;

    for (const auto& import : context.imports) {
        if (import.find("LoadLibrary") != std::string::npos ||
            import.find("GetProcAddress") != std::string::npos) {
            ++dllLoaders;
        }

        if (import.find("VirtualAlloc") != std::string::npos ||
            import.find("VirtualProtect") != std::string::npos ||
            import.find("WriteProcessMemory") != std::string::npos) {
            ++memoryFunctions;
        }

        if (import.find("Internet") != std::string::npos ||
            import.find("Http") != std::string::npos ||
            import.find("Socket") != std::string::npos) {
            ++networkFunctions;
        }

        if (import.find("CreateProcess") != std::string::npos ||
            import.find("OpenProcess") != std::string::npos) {
            ++processFunctions;
        }

        if (import.find("Crypt") != std::string::npos ||
            import.find("BCrypt") != std::string::npos) {
            ++cryptoFunctions;
        }
    }

    output.addNumeric("imports.dll_loading", dllLoaders);
    output.addNumeric("imports.memory_operations", memoryFunctions);
    output.addNumeric("imports.network", networkFunctions);
    output.addNumeric("imports.process", processFunctions);
    output.addNumeric("imports.crypto", cryptoFunctions);
}

} // namespace lulz::ai::features