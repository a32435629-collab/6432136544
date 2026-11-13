#include <cstdint>
#include <set>
#include <vector>
namespace lulz::debugger { class BreakpointTable{std::set<std::uint64_t> points_;public:bool add(std::uint64_t a){return points_.insert(a).second;}bool remove(std::uint64_t a){return points_.erase(a)!=0;}bool contains(std::uint64_t a)const{return points_.contains(a);}void clear(){points_.clear();}std::vector<std::uint64_t> list()const{return {points_.begin(),points_.end()};}}; }