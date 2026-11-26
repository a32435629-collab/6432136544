#pragma once
#include "binary/BinaryImage.hpp"
#include <string>
#include <vector>

namespace lulz::binary {
struct Diagnostic { std::string code, message; std::size_t offset=0; };
struct ValidationReport { bool valid=true; std::vector<Diagnostic> diagnostics; };
ValidationReport validateImage(const BinaryImage& image);
}
