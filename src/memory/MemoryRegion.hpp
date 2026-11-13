#pragma once
#include "lulz/core/Result.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>
namespace lulz::memory {
struct Region { std::uint64_t address=0; std::vector<std::uint8_t> bytes; std::string name; bool readable=true; };
class Image {
 std::vector<Region> regions_;
public:
 explicit Image(std::vector<Region> r={}):regions_(std::move(r)){std::sort(regions_.begin(),regions_.end(),[](const auto&a,const auto&b){return a.address<b.address;});}
 const std::vector<Region>& regions()const noexcept{return regions_;}
 bool contains(std::uint64_t a,std::size_t n=1)const noexcept{if(!n)return true;if(a>std::numeric_limits<std::uint64_t>::max()-n)return false;for(const auto&r:regions_)if(r.readable&&a>=r.address&&a-r.address<=r.bytes.size()&&n<=r.bytes.size()-static_cast<std::size_t>(a-r.address))return true;return false;}
 Result<std::vector<std::uint8_t>> read(std::uint64_t a,std::size_t n)const{if(!n)return Result<std::vector<std::uint8_t>>::success({});if(a>std::numeric_limits<std::uint64_t>::max()-n)return Result<std::vector<std::uint8_t>>::failure("Address range overflow");for(const auto&r:regions_)if(r.readable&&a>=r.address&&a-r.address<=r.bytes.size()){auto off=static_cast<std::size_t>(a-r.address);if(n<=r.bytes.size()-off)return Result<std::vector<std::uint8_t>>::success(std::vector<std::uint8_t>(r.bytes.begin()+static_cast<std::ptrdiff_t>(off),r.bytes.begin()+static_cast<std::ptrdiff_t>(off+n)));}return Result<std::vector<std::uint8_t>>::failure("Range is not inside a readable region");}
};
}