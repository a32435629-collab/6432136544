#include "lulz/asm/x86/X86Decoder.hpp"
#include <iomanip>
#include <sstream>
namespace lulz {
static std::string reg(unsigned n) {
    static const char* names[]={"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
    return names[n&7];
}
std::vector<Instruction> disassembleX86Subset(std::span<const std::uint8_t> b, std::uint64_t) {
    std::vector<Instruction> out;
    for(std::size_t i=0;i<b.size();) {
        Instruction ins; ins.offset=i; ins.size=1; ins.valid=true;
        if(b[i]==0x90) ins.text="nop";
        else if(b[i]==0xc3) ins.text="ret";
        else if(b[i]==0xcc) ins.text="int3";
        else if(i+2<b.size() && b[i]==0x48 && b[i+1]==0x89 && (b[i+2]&0xc0)==0xc0) {
            const unsigned modrm=b[i+2]; ins.text="mov "+reg(modrm&7)+", "+reg((modrm>>3)&7); ins.size=3;
        } else if(i+3<b.size() && b[i]==0x48 && b[i+1]==0x83 && b[i+2]==0xc0) {
            std::ostringstream s; s<<"add rax, "<<static_cast<unsigned>(b[i+3]); ins.text=s.str(); ins.size=4;
        } else if(i+4<b.size() && b[i]==0xe8) {
            std::int32_t rel=static_cast<std::int32_t>(b[i+1] | (b[i+2]<<8) | (b[i+3]<<16) | (b[i+4]<<24));
            std::ostringstream s; s<<"call rel "<<rel; ins.text=s.str(); ins.size=5;
        } else {
            std::ostringstream s; s<<"db 0x"<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(b[i]);
            ins.text=s.str(); ins.valid=false;
        }
        out.push_back(ins); i+=ins.size;
    }
    return out;
}
}
