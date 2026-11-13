#pragma once
#include <algorithm>
#include <string>
#include <utility>
#include <vector>
namespace lulz::ui {
struct Tab{std::string id,title;bool closable=true;};
class Workspace{std::vector<Tab> tabs_;std::string active_;public:
 bool open(Tab t){if(t.id.empty()||t.title.empty()||std::any_of(tabs_.begin(),tabs_.end(),[&](const auto&x){return x.id==t.id;}))return false;active_=t.id;tabs_.push_back(std::move(t));return true;}
 bool close(const std::string&id){auto i=std::find_if(tabs_.begin(),tabs_.end(),[&](const auto&t){return t.id==id;});if(i==tabs_.end()||!i->closable)return false;auto n=static_cast<std::size_t>(i-tabs_.begin());tabs_.erase(i);if(active_==id)active_=tabs_.empty()?std::string{}:tabs_[n<tabs_.size()?n:tabs_.size()-1].id;return true;}
 bool activate(const std::string&id){if(std::none_of(tabs_.begin(),tabs_.end(),[&](const auto&t){return t.id==id;}))return false;active_=id;return true;}
 const std::vector<Tab>&tabs()const noexcept{return tabs_;}const std::string&activeId()const noexcept{return active_;}
};
}