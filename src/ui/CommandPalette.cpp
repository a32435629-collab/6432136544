#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
namespace lulz::ui {struct Command{std::string id,label,description;};static std::string lower(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}std::vector<Command> filter(const std::vector<Command>&v,const std::string&q){auto n=lower(q);std::vector<Command>o;for(auto&c:v)if(n.empty()||lower(c.id).find(n)!=c.id.npos||lower(c.label).find(n)!=c.label.npos||lower(c.description).find(n)!=c.description.npos)o.push_back(c);return o;} }