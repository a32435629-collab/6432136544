#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace lulz::plugins {struct Descriptor{std::string id,name,version;};class Registry{std::map<std::string,Descriptor> p_;public:bool add(Descriptor d){if(d.id.empty()||d.name.empty()||p_.contains(d.id))return false;p_.emplace(d.id,std::move(d));return true;}bool remove(const std::string&id){return p_.erase(id)!=0;}std::optional<Descriptor> find(const std::string&id)const{auto i=p_.find(id);return i==p_.end()?std::nullopt:std::optional<Descriptor>(i->second);}std::vector<Descriptor> list()const{std::vector<Descriptor>v;for(auto&[k,x]:p_){(void)k;v.push_back(x);}return v;}}; }