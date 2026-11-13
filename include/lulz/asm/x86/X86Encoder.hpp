#pragma once
#include "lulz/core/Result.hpp"
#include <cstdint>
#include <string_view>
#include <vector>
namespace lulz {
Result<std::vector<std::uint8_t>> assembleX86Subset(std::string_view source);
}
