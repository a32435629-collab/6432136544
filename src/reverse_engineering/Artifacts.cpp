#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace lulz::reverse_engineering {struct StringRef{std::size_t offset;std::string value;};std::vector<StringRef> extractStrings(std::span<const std::uint8_t>b,std::size_t min=4){std::vector<StringRef>o;std::string s;std::size_t start=0;for(std::size_t i=0;i<=b.size();++i){auto c=i<b.size()?b[i]:0;if(c>=32&&c<=126){if(s.empty())start=i;s+=char(c);}else{if(s.size()>=min)o.push_back({start,std::move(s)});s.clear();}}return o;} }