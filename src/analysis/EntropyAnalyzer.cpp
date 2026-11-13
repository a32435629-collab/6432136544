#include "lulz/analysis/EntropyAnalyzer.hpp"
#include <array>
#include <cmath>
namespace lulz {
double shannonEntropy(std::span<const std::uint8_t> b) {
    if(b.empty()) return 0.0;
    std::array<std::uint64_t,256> counts{};
    for(auto x:b) ++counts[x];
    double h=0.0;
    for(auto n:counts) if(n) { const double p=static_cast<double>(n)/b.size(); h-=p*std::log2(p); }
    return h;
}
}
