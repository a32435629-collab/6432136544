#pragma once
#include <cstdint>
#include <span>
#include <string>
namespace lulz {
std::string detectFormat(std::span<const std::uint8_t> bytes);
}
