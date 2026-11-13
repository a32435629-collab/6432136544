#pragma once
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz::crypto_analysis {
struct ByteStatistics {
    std::array<std::uint64_t,256> frequencies{};
    double entropyBits{};
    double printableRatio{};
    std::size_t size{};
};
inline ByteStatistics analyzeBytes(std::span<const std::uint8_t> bytes) {
    ByteStatistics s; s.size=bytes.size();
    std::uint64_t printable=0;
    for(auto b:bytes) { ++s.frequencies[b]; if((b>=0x20&&b<=0x7e)||b=='\n'||b=='\r'||b=='\t') ++printable; }
    if(!bytes.empty()) {
        for(auto n:s.frequencies) if(n) { const double p=static_cast<double>(n)/bytes.size(); s.entropyBits-=p*std::log2(p); }
        s.printableRatio=static_cast<double>(printable)/bytes.size();
    }
    return s;
}
struct RepeatedBlock { std::size_t firstOffset{}, secondOffset{}, length{}; };
inline std::vector<RepeatedBlock> findRepeatedBlocks(std::span<const std::uint8_t> bytes,
                                                      std::size_t blockSize=16,
                                                      std::size_t maxResults=256) {
    std::vector<RepeatedBlock> out;
    if(blockSize==0 || blockSize>bytes.size() || maxResults==0) return out;
    for(std::size_t a=0;a+blockSize<=bytes.size() && out.size()<maxResults;++a) {
        for(std::size_t b=a+blockSize;b+blockSize<=bytes.size() && out.size()<maxResults;++b) {
            std::size_t n=0;
            while(n<blockSize && bytes[a+n]==bytes[b+n]) ++n;
            if(n==blockSize) out.push_back({a,b,blockSize});
        }
    }
    return out;
}
struct XorCandidate { std::uint8_t key{}; double printableRatio{}; };
inline std::vector<XorCandidate> rankSingleByteXor(std::span<const std::uint8_t> bytes,
                                                   std::size_t limit=8) {
    std::vector<XorCandidate> scores;
    if(bytes.empty()||limit==0) return scores;
    for(unsigned key=0;key<256;++key) {
        std::size_t printable=0;
        for(auto b:bytes) { const auto c=static_cast<std::uint8_t>(b^key);
            if((c>=0x20&&c<=0x7e)||c=='\n'||c=='\r'||c=='\t') ++printable; }
        scores.push_back({static_cast<std::uint8_t>(key),static_cast<double>(printable)/bytes.size()});
    }
    for(std::size_t i=0;i<scores.size();++i) for(std::size_t j=i+1;j<scores.size();++j)
        if(scores[j].printableRatio>scores[i].printableRatio) { auto t=scores[i];scores[i]=scores[j];scores[j]=t; }
    if(scores.size()>limit) scores.resize(limit);
    return scores;
}
} // namespace lulz::crypto_analysis
