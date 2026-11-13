#pragma once
#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace lulz::database {
struct ArtifactRecord {
    std::uint64_t id{};
    std::string name;
    std::string format;
    std::string sha256;
    std::uint64_t size{};
    std::vector<std::string> tags;
};
class AnalysisStore {
public:
    bool insert(ArtifactRecord record) {
        if(record.id==0 || record.name.empty() || records_.contains(record.id)) return false;
        records_.emplace(record.id,std::move(record)); return true;
    }
    bool upsert(ArtifactRecord record) {
        if(record.id==0 || record.name.empty()) return false;
        records_.insert_or_assign(record.id,std::move(record)); return true;
    }
    std::optional<ArtifactRecord> find(std::uint64_t id) const {
        auto it=records_.find(id); if(it==records_.end()) return std::nullopt; return it->second;
    }
    bool erase(std::uint64_t id) { return records_.erase(id)!=0; }
    std::vector<ArtifactRecord> list() const {
        std::vector<ArtifactRecord> out; out.reserve(records_.size());
        for(const auto& item:records_) out.push_back(item.second);
        std::sort(out.begin(),out.end(),[](const auto& a,const auto& b){return a.id<b.id;});
        return out;
    }
    std::vector<ArtifactRecord> findByTag(const std::string& tag) const {
        std::vector<ArtifactRecord> out;
        for(const auto& item:records_) if(std::find(item.second.tags.begin(),item.second.tags.end(),tag)!=item.second.tags.end()) out.push_back(item.second);
        std::sort(out.begin(),out.end(),[](const auto& a,const auto& b){return a.id<b.id;});
        return out;
    }
    std::size_t size() const noexcept { return records_.size(); }
    void clear() noexcept { records_.clear(); }
private:
    std::unordered_map<std::uint64_t,ArtifactRecord> records_;
};
} // namespace lulz::database
