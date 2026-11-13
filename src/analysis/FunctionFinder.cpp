#include "lulz/analysis/FunctionFinder.hpp"
namespace lulz {
std::vector<FunctionCandidate> findX64FunctionCandidates(std::span<const std::uint8_t> b) {
    std::vector<FunctionCandidate> out;
    // Heuristic only: common x64 frame setup and stack-allocation byte patterns.
    for(std::size_t i=0;i+3<b.size();++i) {
        if(b[i]==0x55 && b[i+1]==0x48 && b[i+2]==0x89 && b[i+3]==0xe5)
            out.push_back({i,"push rbp; mov rbp, rsp prologue candidate"});
        else if(i+4<b.size() && b[i]==0x48 && b[i+1]==0x83 && b[i+2]==0xec)
            out.push_back({i,"sub rsp, imm8 stack-frame candidate"});
    }
    return out;
}
}
