#include "lulz/asm/x86/X86Encoder.hpp"
#include <algorithm>
#include <cctype>
namespace lulz {
Result<std::vector<std::uint8_t>> assembleX86Subset(std::string_view src) {
    std::string s; for(unsigned char c:src) if(!std::isspace(c)) s.push_back(static_cast<char>(std::tolower(c)));
    if(s=="nop") return Result<std::vector<std::uint8_t>>::success({0x90});
    if(s=="ret") return Result<std::vector<std::uint8_t>>::success({0xc3});
    if(s=="int3") return Result<std::vector<std::uint8_t>>::success({0xcc});
    if(s=="movrax,rbx") return Result<std::vector<std::uint8_t>>::success({0x48,0x89,0xd8});
    if(s=="addr ax,1" || s=="addrax,1") return Result<std::vector<std::uint8_t>>::success({0x48,0x83,0xc0,0x01});
    return Result<std::vector<std::uint8_t>>::failure("instruction not supported by v0.1 subset encoder");
}
}
