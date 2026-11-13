#pragma once
#include <cstdint>
#include <span>
namespace lulz {
double shannonEntropy(std::span<const std::uint8_t> bytes);
}
