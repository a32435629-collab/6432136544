#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
namespace lulz::diff { struct Hunk{std::size_t offset,leftSize,rightSize;};struct Result{std::size_t changed{};std::vector<Hunk> hunks;};Result compare(std::span<const std::uint8_t>a,std::span<const std::uint8_t>b){Result r;bool active=false;Hunk h{};for(std::size_t i=0,n=std::max(a.size(),b.size());i<n;++i){bool c=i>=a.size()||i>=b.size()||a[i]!=b[i];if(c){++r.changed;if(!active){h={i,0,0};active=true;}if(i<a.size())++h.leftSize;if(i<b.size())++h.rightSize;}else if(active){r.hunks.push_back(h);active=false;}}if(active)r.hunks.push_back(h);return r;} }