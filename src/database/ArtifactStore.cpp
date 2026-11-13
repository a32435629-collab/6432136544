#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <cstdint>
namespace lulz::database { struct Artifact{std::string id,type,origin;std::vector<std::uint8_t> bytes;}; class ArtifactStore{std::map<std::string,Artifact> data_;public:bool put(Artifact a){if(a.id.empty()||a.type.empty())return false;data_.insert_or_assign(a.id,std::move(a));return true;}bool erase(const std::string&id){return data_.erase(id)!=0;}std::optional<Artifact> get(const std::string&id)const{auto i=data_.find(id);return i==data_.end()?std::nullopt:std::optional<Artifact>(i->second);}std::size_t size()const noexcept{return data_.size();}}; }