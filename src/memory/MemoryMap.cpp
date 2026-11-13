#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>
namespace lulz::memory {struct Region{std::uint64_t base,size;bool read,write,execute;std::string name;};class MemoryMap{std::vector<Region> r_;public:bool add(Region x){if(!x.size||x.base>std::numeric_limits<std::uint64_t>::max()-x.size)return false;for(auto&v:r_)if(x.base<v.base+v.size&&v.base<x.base+x.size)return false;r_.push_back(std::move(x));std::sort(r_.begin(),r_.end(),[](auto&a,auto&b){return a.base<b.base;});return true;}std::optional<Region> find(std::uint64_t a)const{auto i=std::upper_bound(r_.begin(),r_.end(),a,[](auto v,const Region&x){return v<x.base;});if(i==r_.begin())return {};--i;return a-i->base<i->size?std::optional<Region>(*i):std::nullopt;}}; }