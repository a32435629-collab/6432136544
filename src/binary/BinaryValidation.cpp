#include "binary/BinaryValidation.hpp"

#include "binary/BinaryView.hpp"

#include <algorithm>
#include <cstdint>

namespace lulz::binary {
namespace {

void error(ValidationReport& report, const char* code,
           const char* message, std::size_t offset) {
    report.valid = false;
    report.diagnostics.push_back({code, message, offset});
}

bool startsWith(const std::vector<std::uint8_t>& bytes,
                std::initializer_list<std::uint8_t> signature) {
    if (bytes.size() < signature.size()) return false;
    return std::equal(signature.begin(), signature.end(), bytes.begin());
}

bool isPartialPrefix(const std::vector<std::uint8_t>& bytes,
                     std::initializer_list<std::uint8_t> signature) {
    return !bytes.empty() && bytes.size() < signature.size() &&
           std::equal(bytes.begin(), bytes.end(), signature.begin());
}

} // namespace

ValidationReport validateImage(const BinaryImage& image,
                               const ValidationOptions& options) {
    ValidationReport report;
    const auto& bytes = image.bytes();
    const auto size = image.size();

    if (size == 0) {
        error(report, "BIN_EMPTY", "Input is empty", 0);
        return report;
    }
    if (static_cast<std::uintmax_t>(size) > options.maxBytes) {
        error(report, "BIN_SIZE_LIMIT", "Input exceeds configured validation size limit", 0);
        return report;
    }

    if (!options.validateKnownHeader) return report;

    if (isPartialPrefix(bytes, {0x7f, 'E', 'L', 'F'}) ||
        isPartialPrefix(bytes, {0x50, 0x4b, 0x03, 0x04}) ||
        isPartialPrefix(bytes, {0x1f, 0x8b})) {
        error(report, "BIN_TRUNCATED_SIGNATURE", "Input ends inside a recognized file signature", 0);
        return report;
    }

    if (bytes[0] == 'M' && (size == 1 || (size >= 2 && bytes[1] == 'Z'))) {
        if (size < 64) {
            error(report, "PE_DOS_HEADER_TRUNCATED", "MZ input is shorter than the DOS header", 0);
            return report;
        }
        BinaryView view(image);
        const auto peOffset = view.u32le(0x3c);
        if (!peOffset) {
            error(report, "PE_E_LFANEW_MISSING", "DOS header does not contain e_lfanew", 0x3c);
            return report;
        }
        const auto offset = static_cast<std::size_t>(*peOffset);
        if (!image.contains(offset, 24)) {
            error(report, "PE_NT_HEADERS_TRUNCATED", "PE signature and COFF header extend beyond the file", offset);
            return report;
        }
        const auto signature = view.u32le(offset);
        if (!signature || *signature != 0x00004550u) {
            error(report, "PE_SIGNATURE_INVALID", "MZ input does not contain a valid PE signature at e_lfanew", offset);
            return report;
        }
        return report;
    }

    if (startsWith(bytes, {0x7f, 'E', 'L', 'F'})) {
        if (size < 16) {
            error(report, "ELF_IDENT_TRUNCATED", "ELF identification is truncated", 0);
            return report;
        }
        if (bytes[4] != 1 && bytes[4] != 2) {
            error(report, "ELF_CLASS_INVALID", "ELF class must be ELF32 or ELF64", 4);
            return report;
        }
        if (bytes[5] != 1) {
            error(report, "ELF_ENDIAN_UNSUPPORTED", "Only little-endian ELF is supported", 5);
            return report;
        }
        if (bytes[6] != 1) {
            error(report, "ELF_VERSION_INVALID", "Unsupported ELF identification version", 6);
            return report;
        }
        const std::size_t minimumHeader = bytes[4] == 2 ? 64 : 52;
        if (size < minimumHeader) {
            error(report, "ELF_HEADER_TRUNCATED", "ELF header is shorter than its class minimum", size);
            return report;
        }
        BinaryView view(image);
        const auto headerSize = view.u16le(bytes[4] == 2 ? 52 : 40);
        if (!headerSize || *headerSize < minimumHeader) {
            error(report, "ELF_EHSIZE_INVALID", "ELF e_ehsize is smaller than the required header", bytes[4] == 2 ? 52 : 40);
            return report;
        }
        if (*headerSize > size) {
            error(report, "ELF_EHSIZE_RANGE", "ELF e_ehsize extends beyond the file", bytes[4] == 2 ? 52 : 40);
            return report;
        }
        return report;
    }

    if (size >= 4) {
        BinaryView view(image);
        const auto magic = view.u32le(0);
        if (magic && (*magic == 0xfeedfaceu || *magic == 0xfeedfacfu)) {
            const std::size_t minimumHeader = *magic == 0xfeedfacfu ? 32 : 28;
            if (size < minimumHeader)
                error(report, "MACHO_HEADER_TRUNCATED", "Mach-O header is truncated", size);
            return report;
        }
    }

    // Unknown data is allowed: BinaryImage is also used for raw blobs and
    // embedded payloads. Format recognition is the responsibility of the parser.
    return report;
}

} // namespace lulz::binary
