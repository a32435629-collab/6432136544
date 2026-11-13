#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lulz::diff {
struct ByteRange { std::size_t offset{}, length{}; };
struct BinaryDiffResult {
    std::vector<ByteRange> changed;
    std::size_t leftSize{}, rightSize{}, equalBytes{}, changedBytes{};
    bool identical() const noexcept { return changed.empty() && leftSize==rightSize; }
};
inline BinaryDiffResult compareBytes(std::span<const std::uint8_t> left,
                                     std::span<const std::uint8_t> right,
                                     std::size_t maxRanges=100000) {
    BinaryDiffResult r; r.leftSize=left.size(); r.rightSize=right.size();
    const auto common=std::min(left.size(),right.size());
    bool active=false; std::size_t start=0;
    auto close=[&](std::size_t end) { if(active) { if(r.changed.size()<maxRanges) r.changed.push_back({start,end-start}); active=false; } };
    for(std::size_t i=0;i<common;++i) {
        if(left[i]==right[i]) { ++r.equalBytes; close(i); }
        else { ++r.changedBytes; if(!active) { active=true; start=i; } }
    }
    close(common);
    if(left.size()!=right.size()) {
        const auto tail=left.size()>right.size()?left.size()-common:right.size()-common;
        r.changedBytes+=tail;
        if(tail && r.changed.size()<maxRanges) r.changed.push_back({common,tail});
    }
    return r;
}
} // namespace lulz::diff
