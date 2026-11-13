#pragma once
#include "lulz/core/Result.hpp"
#include <cstdint>
#include <string_view>
#include <vector>
namespace lulz {
Result<std::vector<std::uint8_t>> parseHex(std::string_view text);
std::string formatHex(const std::vector<std::uint8_t>& bytes, std::size_t columns = 16);
}
