#pragma once
#include "lulz/core/Result.hpp"
#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>
namespace lulz::plugins {
struct Manifest{std::string id,name,version,description;};
class Registry{std::unordered_map<std::string,Manifest> items_;public:
 Result<bool> add(Manifest m){if(m.id.empty()||m.name.empty()||m.version.empty())return Result<bool>::failure("Plugin id, name and version are required");if(m.id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")!=std::string::npos)return Result<bool>::failure("Invalid plugin id");if(items_.contains(m.id))return Result<bool>::failure("Plugin already registered");items_.emplace(m.id,std::move(m));return Result<bool>::success(true);}
 bool remove(const std::string&id){return items_.erase(id)!=0;}
 const Manifest* find(const std::string&id)const noexcept{auto i=items_.find(id);return i==items_.end()?nullptr:&i->second;}
 std::vector<Manifest> list()const{std::vector<Manifest>v;for(const auto&x:items_)v.push_back(x.second);std::sort(v.begin(),v.end(),[](const auto&a,const auto&b){return a.id<b.id;});return v;}
};
}