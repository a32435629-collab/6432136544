#pragma once

#include "binary/BinaryImage.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace lulz::binary {

struct Diagnostic {
    std::string code;
    std::string message;
    std::size_t offset = 0;
};

struct ValidationOptions {
    // Validation limit is independent of the loader limit, so in-memory images
    // created by callers are subject to the same policy.
    std::uintmax_t maxBytes = 512ull * 1024ull * 1024ull;
    bool validateKnownHeader = true;
};

struct ValidationReport {
    bool valid = true;
    std::vector<Diagnostic> diagnostics;
};

ValidationReport validateImage(
    const BinaryImage& image,
    const ValidationOptions& options = {});

} // namespace lulz::binary
