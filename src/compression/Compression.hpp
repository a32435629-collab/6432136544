#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lulz::compression {
struct DecodeResult { std::vector<std::uint8_t> bytes; std::size_t consumed{}; };
struct Limits { std::size_t maxOutputBytes{64u * 1024u * 1024u}; };

// PackBits-like: control < 128 => control+1 literal bytes;
// control >= 128 => (control & 127)+3 copies of the following byte.
inline std::vector<std::uint8_t> encodeRle(std::span<const std::uint8_t> input) {
    std::vector<std::uint8_t> out;
    for (std::size_t i=0; i<input.size();) {
        std::size_t run=1;
        while (i+run<input.size() && input[i+run]==input[i] && run<130) ++run;
        if (run>=3) {
            out.push_back(static_cast<std::uint8_t>(0x80u | (run-3)));
            out.push_back(input[i]); i+=run; continue;
        }
        const auto start=i;
        while (i<input.size() && i-start<128) {
            run=1;
            while (i+run<input.size() && input[i+run]==input[i] && run<130) ++run;
            if (run>=3) break;
            const auto take=run < 128-(i-start) ? run : 128-(i-start);
            i+=take;
            if(take<run) break;
        }
        const auto count=i-start;
        out.push_back(static_cast<std::uint8_t>(count-1));
        out.insert(out.end(),input.begin()+static_cast<std::ptrdiff_t>(start),
                   input.begin()+static_cast<std::ptrdiff_t>(i));
    }
    return out;
}
inline bool decodeRle(std::span<const std::uint8_t> input, std::vector<std::uint8_t>& output,
                      Limits limits={}, std::string* error=nullptr) {
    output.clear();
    auto fail=[&](const char* why){ output.clear(); if(error)*error=why; return false; };
    for (std::size_t i=0;i<input.size();) {
        const auto control=input[i++];
        const std::size_t count=control<128 ? std::size_t(control)+1 : std::size_t(control&127u)+3;
        if(output.size()>limits.maxOutputBytes || count>limits.maxOutputBytes-output.size()) return fail("RLE output limit exceeded");
        if (control<128) {
            if (count>input.size()-i) return fail("truncated RLE literal");
            output.insert(output.end(),input.begin()+static_cast<std::ptrdiff_t>(i),
                          input.begin()+static_cast<std::ptrdiff_t>(i+count)); i+=count;
        } else {
            if (i>=input.size()) return fail("truncated RLE run");
            output.insert(output.end(),count,input[i++]);
        }
    }
    if(error) error->clear();
    return true;
}
inline bool decodeRle(std::span<const std::uint8_t> input, DecodeResult& result,
                      Limits limits={}, std::string* error=nullptr) {
    if(!decodeRle(input,result.bytes,limits,error)) return false;
    result.consumed=input.size(); return true;
}
} // namespace lulz::compression
