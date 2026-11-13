#include <array>
#include <cmath>
#include <cstdint>
#include <span>
namespace lulz::crypto_analysis { double entropy(std::span<const std::uint8_t>b) noexcept {if(b.empty())return 0;std::array<std::size_t,256> f{};for(auto x:b)++f[x];double h=0;for(auto n:f)if(n){double p=double(n)/double(b.size());h-=p*std::log2(p);}return h;} bool highEntropy(std::span<const std::uint8_t>b,double t=7.2) noexcept{return b.size()>=32&&t>=0&&t<=8&&entropy(b)>=t;} }