#include "lulz/hex/HexParser.hpp"
#include <cctype>
namespace lulz {
Result<std::vector<std::uint8_t>> parseHex(std::string_view text) {
    std::vector<std::uint8_t> out;
    int high=-1;
    for (unsigned char c : text) {
        if (std::isspace(c) || c=='_' || c==':' || c=='-') continue;
        int n = c>='0'&&c<='9' ? c-'0' : c>='a'&&c<='f' ? c-'a'+10 : c>='A'&&c<='F' ? c-'A'+10 : -1;
        if (n<0) return Result<std::vector<std::uint8_t>>::failure("invalid hex character");
        if (high<0) high=n;
        else { out.push_back(static_cast<std::uint8_t>((high<<4)|n)); high=-1; }
    }
    if (high>=0) return Result<std::vector<std::uint8_t>>::failure("odd number of hex digits");
    return Result<std::vector<std::uint8_t>>::success(std::move(out));
}
}
