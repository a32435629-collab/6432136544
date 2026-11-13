
#pragma once

#include "lulz/core/Result.hpp"
#include "lulz/formats/pe/PEParser.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz {

struct UnwindOperation {
    std::uint8_t codeOffset{};
    std::uint8_t opcode{};
    std::uint8_t opInfo{};

    std::string name;

    std::uint32_t value{};
    std::string detail;
};

struct UnwindInfo {
    std::uint8_t version{};
    std::uint8_t flags{};
    std::uint8_t prologSize{};
    std::uint8_t codeSlots{};
    std::uint8_t frameRegister{};
    std::uint8_t frameOffset{};

    // Total stack consumption, including PUSH operations.
    std::uint32_t stackAllocation{};

    // UWOP_ALLOC_* and machine-frame allocation.
    std::uint32_t explicitAllocation{};

    std::vector<std::string> savedRegisters;
    std::vector<std::string> savedXmmRegisters;
    std::vector<UnwindOperation> operations;

    bool hasExceptionHandler{};
    bool hasTerminationHandler{};
    bool chained{};

    std::uint32_t handlerRva{};

    RuntimeFunctionEntry chainedFunction{};

    std::size_t fileOffset{};
};

Result<UnwindInfo> parsePEUnwindInfo(
    std::span<const std::uint8_t> bytes,
    const PEInfo& pe,
    const RuntimeFunctionEntry& function
);

std::string unwindInfoToJson(
    const RuntimeFunctionEntry& function,
    const UnwindInfo& info
);

} // namespace lulz
