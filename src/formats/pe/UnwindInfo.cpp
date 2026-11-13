
#include "lulz/formats/pe/UnwindInfo.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

namespace lulz {
namespace {

std::optional<std::size_t> mapRva(
    std::span<const std::uint8_t> bytes,
    const PEInfo& pe,
    std::uint32_t rva,
    std::size_t size
) {
    const std::uint64_t target = rva;

    for (const auto& section : pe.sections) {
        const std::uint64_t start = section.virtualAddress;

        if (target < start) {
            continue;
        }

        const std::uint64_t delta = target - start;
        const std::uint64_t rawSize = section.rawSize;

        if (delta >= rawSize || size > rawSize - delta) {
            continue;
        }

        const std::uint64_t raw =
            std::uint64_t(section.rawOffset) + delta;

        if (raw > bytes.size() ||
            size > bytes.size() - static_cast<std::size_t>(raw)) {
            return std::nullopt;
        }

        return static_cast<std::size_t>(raw);
    }

    return std::nullopt;
}

std::string regName(unsigned reg) {
    static constexpr const char* names[] = {
        "RAX", "RCX", "RDX", "RBX",
        "RSP", "RBP", "RSI", "RDI",
        "R8", "R9", "R10", "R11",
        "R12", "R13", "R14", "R15"
    };

    return reg < 16 ? names[reg] : "UNKNOWN";
}

std::string xmmName(unsigned reg) {
    return "XMM" + std::to_string(reg);
}

std::string jsonEscape(const std::string& value) {
    std::ostringstream out;

    for (unsigned char ch : value) {
        switch (ch) {
        case '"':  out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;

        default:
            if (ch < 0x20) {
                static constexpr char hex[] = "0123456789abcdef";
                out << "\\u00"
                    << hex[ch >> 4]
                    << hex[ch & 0x0F];
            } else {
                out << static_cast<char>(ch);
            }
        }
    }

    return out.str();
}

bool addStackAllocation(UnwindInfo& info, std::uint32_t amount) {
    if (amount > std::numeric_limits<std::uint32_t>::max()
                     - info.stackAllocation) {
        return false;
    }

    info.stackAllocation += amount;
    return true;
}

bool addExplicitAllocation(UnwindInfo& info, std::uint32_t amount) {
    if (amount > std::numeric_limits<std::uint32_t>::max()
                     - info.explicitAllocation) {
        return false;
    }

    info.explicitAllocation += amount;
    return true;
}

} // namespace

Result<UnwindInfo> parsePEUnwindInfo(
    std::span<const std::uint8_t> bytes,
    const PEInfo& pe,
    const RuntimeFunctionEntry& function
) {
    if (!pe.is64) {
        return Result<UnwindInfo>::failure(
            "UNWIND_INFO parser supports x64 PE32+ only"
        );
    }

    if (function.unwindInfoRva == 0) {
        return Result<UnwindInfo>::failure(
            "RUNTIME_FUNCTION has null UNWIND_INFO RVA"
        );
    }

    const auto headerOffset = mapRva(
        bytes, pe, function.unwindInfoRva, 4
    );

    if (!headerOffset) {
        return Result<UnwindInfo>::failure(
            "UNWIND_INFO header is outside raw PE section data"
        );
    }

    const std::size_t offset = *headerOffset;

    auto u8 = [&](std::size_t pos) -> std::uint8_t {
        return bytes[pos];
    };

    auto u16 = [&](std::size_t pos) -> std::uint16_t {
        return static_cast<std::uint16_t>(
            std::uint16_t(u8(pos)) |
            (std::uint16_t(u8(pos + 1)) << 8)
        );
    };

    auto u32 = [&](std::size_t pos) -> std::uint32_t {
        return std::uint32_t(u16(pos)) |
            (std::uint32_t(u16(pos + 2)) << 16);
    };

    UnwindInfo out;
    out.fileOffset = offset;

    const std::uint8_t versionAndFlags = u8(offset);

    out.version = versionAndFlags & 0x07;
    out.flags = versionAndFlags >> 3;
    out.prologSize = u8(offset + 1);
    out.codeSlots = u8(offset + 2);

    const std::uint8_t frame = u8(offset + 3);

    out.frameRegister = frame & 0x0F;
    out.frameOffset = frame >> 4;

    if (out.version != 1 && out.version != 2) {
        return Result<UnwindInfo>::failure(
            "unsupported UNWIND_INFO version"
        );
    }

    if ((out.flags & ~0x07) != 0) {
        return Result<UnwindInfo>::failure(
            "invalid UNWIND_INFO flags"
        );
    }

    if ((out.flags & 0x04) != 0 &&
        (out.flags & 0x03) != 0) {
        return Result<UnwindInfo>::failure(
            "CHAININFO cannot be combined with handler flags"
        );
    }

    const auto isNonVolatileGpr = [](unsigned reg) {
        return reg == 3 || reg == 5 || reg == 6 || reg == 7 ||
               (reg >= 12 && reg <= 15);
    };

    if (out.frameRegister != 0 && !isNonVolatileGpr(out.frameRegister)) {
        return Result<UnwindInfo>::failure(
            "frame register is not a nonvolatile GPR"
        );
    }

    if (out.frameRegister == 0 && out.frameOffset != 0) {
        return Result<UnwindInfo>::failure(
            "frame offset is set without a frame register"
        );
    }

    const std::size_t codesOffset = offset + 4;
    const std::size_t codesSize =
        std::size_t(out.codeSlots) * 2;

    if (codesOffset > bytes.size() ||
        codesSize > bytes.size() - codesOffset) {
        return Result<UnwindInfo>::failure(
            "truncated UNWIND_CODE array"
        );
    }

    const std::size_t alignedSlots =
        (std::size_t(out.codeSlots) + 1) & ~std::size_t(1);

    const std::size_t alignedCodesSize = alignedSlots * 2;

    const auto codesSectionOffset = mapRva(
        bytes, pe, function.unwindInfoRva,
        4 + alignedCodesSize
    );
    if (!codesSectionOffset || *codesSectionOffset != offset) {
        return Result<UnwindInfo>::failure(
            "UNWIND_CODE array crosses section or file boundary"
        );
    }

    auto slotValue = [&](std::size_t slot) -> std::uint16_t {
        return u16(codesOffset + slot * 2);
    };

    auto need = [&](std::size_t slot, std::size_t count) {
        return slot <= out.codeSlots &&
            count <= std::size_t(out.codeSlots) - slot;
    };

    std::size_t slot = 0;
    int previousCodeOffset = 256;

    while (slot < out.codeSlots) {
        const std::uint16_t raw = slotValue(slot);

        const std::uint8_t codeOff =
            static_cast<std::uint8_t>(raw & 0xFF);

        const std::uint8_t op =
            static_cast<std::uint8_t>((raw >> 8) & 0x0F);

        const std::uint8_t oi =
            static_cast<std::uint8_t>((raw >> 12) & 0x0F);

        const bool v2Special =
            out.version == 2 && (op == 6 || op == 7);

        if (!v2Special) {
            if (codeOff > out.prologSize) {
                return Result<UnwindInfo>::failure(
                    "UNWIND_CODE offset exceeds prolog size: "
                    "version=" + std::to_string(out.version) +
                    ", prologSize=" + std::to_string(out.prologSize) +
                    ", codeOffset=" + std::to_string(codeOff) +
                    ", opcode=" + std::to_string(op) +
                    ", opInfo=" + std::to_string(oi) +
                    ", slot=" + std::to_string(slot) +
                    ", unwindRva=" +
                    std::to_string(function.unwindInfoRva)
                );
            }

            if (out.version == 1 &&
                int(codeOff) > previousCodeOffset) {
                return Result<UnwindInfo>::failure(
                    "UNWIND_CODE entries are not in descending code-offset order"
                );
            }

            previousCodeOffset = codeOff;
        }

        UnwindOperation item;
        item.codeOffset = codeOff;
        item.opcode = op;
        item.opInfo = oi;

        std::size_t extra = 0;
        std::uint64_t value = 0;

        switch (op) {
        case 0: // UWOP_PUSH_NONVOL
            if (!isNonVolatileGpr(oi)) {
                return Result<UnwindInfo>::failure(
                    "UWOP_PUSH_NONVOL uses a volatile or invalid register"
                );
            }
            item.name = "UWOP_PUSH_NONVOL";
            item.detail = "push nonvolatile register " + regName(oi);
            item.value = 8;

            if (!addStackAllocation(out, 8)) {
                return Result<UnwindInfo>::failure(
                    "stack allocation overflow"
                );
            }

            out.savedRegisters.push_back(regName(oi));
            break;

        case 1: // UWOP_ALLOC_LARGE
            if (oi == 0) {
                item.name = "UWOP_ALLOC_LARGE";
                extra = 1;

                if (!need(slot, 2)) {
                    return Result<UnwindInfo>::failure(
                        "truncated UWOP_ALLOC_LARGE"
                    );
                }

                value = std::uint64_t(slotValue(slot + 1)) * 8;
            } else if (oi == 1) {
                item.name = "UWOP_ALLOC_LARGE_FAR";
                extra = 2;

                if (!need(slot, 3)) {
                    return Result<UnwindInfo>::failure(
                        "truncated UWOP_ALLOC_LARGE_FAR"
                    );
                }

                value =
                    std::uint64_t(slotValue(slot + 1)) |
                    (std::uint64_t(slotValue(slot + 2)) << 16);
            } else {
                return Result<UnwindInfo>::failure(
                    "invalid UWOP_ALLOC_LARGE OpInfo"
                );
            }

            if (value > std::numeric_limits<std::uint32_t>::max()) {
                return Result<UnwindInfo>::failure(
                    "UWOP_ALLOC_LARGE value overflow"
                );
            }

            item.value = static_cast<std::uint32_t>(value);
            item.detail = "stack allocation " +
                std::to_string(item.value) + " bytes";

            if (!addStackAllocation(out, item.value) ||
                !addExplicitAllocation(out, item.value)) {
                return Result<UnwindInfo>::failure(
                    "stack allocation overflow"
                );
            }
            break;

        case 2: // UWOP_ALLOC_SMALL
            item.name = "UWOP_ALLOC_SMALL";
            item.value = std::uint32_t(oi) * 8 + 8;
            item.detail = "stack allocation " +
                std::to_string(item.value) + " bytes";

            if (!addStackAllocation(out, item.value) ||
                !addExplicitAllocation(out, item.value)) {
                return Result<UnwindInfo>::failure(
                    "stack allocation overflow"
                );
            }
            break;

        case 3: // UWOP_SET_FPREG
            if (oi != 0) {
                return Result<UnwindInfo>::failure(
                    "invalid UWOP_SET_FPREG OpInfo"
                );
            }

            if (out.frameRegister == 0) {
                return Result<UnwindInfo>::failure(
                    "UWOP_SET_FPREG without frame register"
                );
            }

            item.name = "UWOP_SET_FPREG";
            item.detail = "establish frame register " +
                regName(out.frameRegister);
            break;

        case 4: // UWOP_SAVE_NONVOL
            if (!isNonVolatileGpr(oi)) {
                return Result<UnwindInfo>::failure(
                    "UWOP_SAVE_NONVOL uses a volatile or invalid register"
                );
            }
            item.name = "UWOP_SAVE_NONVOL";
            extra = 1;

            if (!need(slot, 2)) {
                return Result<UnwindInfo>::failure(
                    "truncated UWOP_SAVE_NONVOL"
                );
            }

            item.value =
                std::uint32_t(slotValue(slot + 1)) * 8;

            item.detail = "save " + regName(oi) +
                " at stack offset " + std::to_string(item.value);

            out.savedRegisters.push_back(regName(oi));
            break;

        case 5: // UWOP_SAVE_NONVOL_FAR
            if (!isNonVolatileGpr(oi)) {
                return Result<UnwindInfo>::failure(
                    "UWOP_SAVE_NONVOL_FAR uses a volatile or invalid register"
                );
            }
            item.name = "UWOP_SAVE_NONVOL_FAR";
            extra = 2;

            if (!need(slot, 3)) {
                return Result<UnwindInfo>::failure(
                    "truncated UWOP_SAVE_NONVOL_FAR"
                );
            }

            item.value =
                std::uint32_t(slotValue(slot + 1)) |
                (std::uint32_t(slotValue(slot + 2)) << 16);

            item.detail = "save " + regName(oi) +
                " at stack offset " + std::to_string(item.value);

            out.savedRegisters.push_back(regName(oi));
            break;

        case 6:
            if (out.version == 2) {
                item.name = "UWOP_EPILOG";

                if (oi == 0) {
                    extra = 1;

                    if (!need(slot, 2)) {
                        return Result<UnwindInfo>::failure(
                            "truncated UWOP_EPILOG"
                        );
                    }

                    item.value = slotValue(slot + 1);
                } else if (oi == 1) {
                    item.value = codeOff;
                } else {
                    return Result<UnwindInfo>::failure(
                        "invalid UWOP_EPILOG OpInfo"
                    );
                }

                item.detail = "epilog metadata, offset " +
                    std::to_string(item.value);
            } else {
                return Result<UnwindInfo>::failure(
                    "reserved opcode 6 in UNWIND_INFO version 1"
                );
            }
            break;

        case 7:
            if (out.version == 2) {
                item.name = "UWOP_SPARE_CODE";
                item.detail = "version 2 spare opcode";
            } else {
                return Result<UnwindInfo>::failure(
                    "reserved opcode 7 in UNWIND_INFO version 1"
                );
            }
            break;

        case 8: // UWOP_SAVE_XMM128
            if (oi < 6) {
                return Result<UnwindInfo>::failure(
                    "UWOP_SAVE_XMM128 must reference XMM6-XMM15"
                );
            }
            item.name = "UWOP_SAVE_XMM128";
            extra = 1;

            if (!need(slot, 2)) {
                return Result<UnwindInfo>::failure(
                    "truncated UWOP_SAVE_XMM128"
                );
            }

            item.value =
                std::uint32_t(slotValue(slot + 1)) * 16;

            item.detail = "save " + xmmName(oi) +
                " at stack offset " + std::to_string(item.value);

            out.savedXmmRegisters.push_back(xmmName(oi));
            break;

        case 9: // UWOP_SAVE_XMM128_FAR
            if (oi < 6) {
                return Result<UnwindInfo>::failure(
                    "UWOP_SAVE_XMM128_FAR must reference XMM6-XMM15"
                );
            }
            item.name = "UWOP_SAVE_XMM128_FAR";
            extra = 2;

            if (!need(slot, 3)) {
                return Result<UnwindInfo>::failure(
                    "truncated UWOP_SAVE_XMM128_FAR"
                );
            }

            item.value =
                std::uint32_t(slotValue(slot + 1)) |
                (std::uint32_t(slotValue(slot + 2)) << 16);

            item.detail = "save " + xmmName(oi) +
                " at stack offset " + std::to_string(item.value);

            out.savedXmmRegisters.push_back(xmmName(oi));
            break;

        case 10: // UWOP_PUSH_MACHFRAME
            if (oi > 1) {
                return Result<UnwindInfo>::failure(
                    "invalid UWOP_PUSH_MACHFRAME OpInfo"
                );
            }

            item.name = "UWOP_PUSH_MACHFRAME";
            item.value = oi == 0 ? 40 : 48;
            item.detail = "machine frame, " +
                std::to_string(item.value) + " bytes";

            if (!addStackAllocation(out, item.value) ||
                !addExplicitAllocation(out, item.value)) {
                return Result<UnwindInfo>::failure(
                    "machine frame allocation overflow"
                );
            }
            break;

        default:
            return Result<UnwindInfo>::failure(
                "unsupported UNWIND_CODE opcode: " +
                std::to_string(op)
            );
        }

        out.operations.push_back(std::move(item));
        slot += 1 + extra;
    }

    const std::size_t tailOffset =
        codesOffset + alignedCodesSize;

    if ((out.flags & 0x04) != 0) {
        out.chained = true;

        const auto tailRva = std::uint64_t(function.unwindInfoRva) +
            4 + alignedCodesSize;
        const auto tailSectionOffset = tailRva <= 0xffffffffu
            ? mapRva(bytes, pe, static_cast<std::uint32_t>(tailRva), 12)
            : std::nullopt;
        if (!tailSectionOffset || *tailSectionOffset != tailOffset) {
            return Result<UnwindInfo>::failure(
                "chained RUNTIME_FUNCTION crosses section or file boundary"
            );
        }

        out.chainedFunction.beginRva = u32(tailOffset);
        out.chainedFunction.endRva = u32(tailOffset + 4);
        out.chainedFunction.unwindInfoRva = u32(tailOffset + 8);
        out.chainedFunction.fileOffset = tailOffset;

        if (out.chainedFunction.beginRva >=
            out.chainedFunction.endRva) {
            return Result<UnwindInfo>::failure(
                "invalid chained RUNTIME_FUNCTION range"
            );
        }

        if (out.chainedFunction.unwindInfoRva == 0) {
            return Result<UnwindInfo>::failure(
                "chained RUNTIME_FUNCTION has null UNWIND_INFO RVA"
            );
        }
        if (out.chainedFunction.endRva > 0x100000000ull) {
            return Result<UnwindInfo>::failure(
                "chained RUNTIME_FUNCTION range overflows RVA space"
            );
        }
    } else if ((out.flags & 0x03) != 0) {
        const auto tailRva = std::uint64_t(function.unwindInfoRva) +
            4 + alignedCodesSize;
        const auto tailSectionOffset = tailRva <= 0xffffffffu
            ? mapRva(bytes, pe, static_cast<std::uint32_t>(tailRva), 4)
            : std::nullopt;
        if (!tailSectionOffset || *tailSectionOffset != tailOffset) {
            return Result<UnwindInfo>::failure(
                "exception handler RVA crosses section or file boundary"
            );
        }

        out.handlerRva = u32(tailOffset);
        out.hasExceptionHandler = (out.flags & 0x01) != 0;
        out.hasTerminationHandler = (out.flags & 0x02) != 0;

        if (out.handlerRva == 0) {
            return Result<UnwindInfo>::failure(
                "exception handler RVA is null"
            );
        }
    }

    return Result<UnwindInfo>::success(std::move(out));
}

std::string unwindInfoToJson(
    const RuntimeFunctionEntry& function,
    const UnwindInfo& info
) {
    std::ostringstream out;

    out << "{\n";
    out << "  \"begin_rva\": " << function.beginRva << ",\n";
    out << "  \"end_rva\": " << function.endRva << ",\n";
    out << "  \"unwind_info_rva\": "
        << function.unwindInfoRva << ",\n";
    out << "  \"file_offset\": " << info.fileOffset << ",\n";
    out << "  \"version\": " << unsigned(info.version) << ",\n";
    out << "  \"flags\": " << unsigned(info.flags) << ",\n";
    out << "  \"prolog_size\": " << unsigned(info.prologSize) << ",\n";
    out << "  \"code_slots\": " << unsigned(info.codeSlots) << ",\n";
    out << "  \"frame_register\": \""
        << jsonEscape(regName(info.frameRegister)) << "\",\n";
    out << "  \"frame_offset\": "
        << unsigned(info.frameOffset) << ",\n";
    out << "  \"stack_allocation\": "
        << info.stackAllocation << ",\n";
    out << "  \"explicit_allocation\": "
        << info.explicitAllocation << ",\n";
    out << "  \"has_exception_handler\": "
        << (info.hasExceptionHandler ? "true" : "false") << ",\n";
    out << "  \"has_termination_handler\": "
        << (info.hasTerminationHandler ? "true" : "false") << ",\n";
    out << "  \"chained\": "
        << (info.chained ? "true" : "false") << ",\n";
    out << "  \"handler_rva\": " << info.handlerRva << ",\n";

    out << "  \"saved_registers\": [";

    for (std::size_t i = 0; i < info.savedRegisters.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << jsonEscape(info.savedRegisters[i]) << "\"";
    }

    out << "],\n  \"saved_xmm_registers\": [";

    for (std::size_t i = 0; i < info.savedXmmRegisters.size(); ++i) {
        if (i != 0) out << ", ";
        out << "\"" << jsonEscape(info.savedXmmRegisters[i]) << "\"";
    }

    out << "],\n  \"operations\": [\n";

    for (std::size_t i = 0; i < info.operations.size(); ++i) {
        const auto& op = info.operations[i];

        out << "    {\n";
        out << "      \"code_offset\": "
            << unsigned(op.codeOffset) << ",\n";
        out << "      \"opcode\": "
            << unsigned(op.opcode) << ",\n";
        out << "      \"op_info\": "
            << unsigned(op.opInfo) << ",\n";
        out << "      \"name\": \""
            << jsonEscape(op.name) << "\",\n";
        out << "      \"value\": " << op.value << ",\n";
        out << "      \"detail\": \""
            << jsonEscape(op.detail) << "\"\n";
        out << "    }";

        if (i + 1 < info.operations.size()) {
            out << ",";
        }

        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";

    return out.str();
}

} // namespace lulz
