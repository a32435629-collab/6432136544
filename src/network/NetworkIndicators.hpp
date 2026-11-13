#pragma once
#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>
namespace lulz::network {
struct Endpoint {std::string host;unsigned short port=0;bool tls=false;std::string path;};
struct Indicator {std::string value,source;};
inline bool validHost(const std::string&h)noexcept{if(h.empty()||h.size()>253||h.front()=='.'||h.back()=='.')return false;for(unsigned char c:h)if(!(std::isalnum(c)||c=='.'||c=='-'))return false;return true;}
inline std::vector<Indicator> extractIndicators(const std::string&s){std::vector<Indicator> out;std::unordered_set<std::string> seen;std::size_t p=0;while((p=s.find("://",p))!=std::string::npos){auto start=p;while(start>0){unsigned char c=s[start-1];if(std::isalnum(c)||c=='+'||c=='-'||c=='.')--start;else break;}auto scheme=s.substr(start,p-start);std::transform(scheme.begin(),scheme.end(),scheme.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});auto end=s.find_first_of("/\\?# \t\r\n\"'<>",p+3);if(end==std::string::npos)end=s.size();auto authority=s.substr(p+3,end-p-3);auto at=authority.rfind('@');if(at!=std::string::npos)authority.erase(0,at+1);if(authority.find('[')==std::string::npos){auto colon=authority.find(':');if(colon!=std::string::npos)authority.resize(colon);std::transform(authority.begin(),authority.end(),authority.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});if(validHost(authority)&&seen.insert(authority).second)out.push_back({authority,"url:"+scheme});}p=end;}return out;}
}