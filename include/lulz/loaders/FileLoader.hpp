#pragma once
#include "lulz/core/Result.hpp"
#include <cstdint>
#include <filesystem>
#include <vector>
namespace lulz {
Result<std::vector<std::uint8_t>> loadFile(const std::filesystem::path& path);
}
