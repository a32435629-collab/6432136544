#pragma once
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace lulz::decompiler {
enum class OpKind { Assign, Add, Subtract, Compare, Call, Return, Jump, ConditionalJump, Comment };
struct Operation { OpKind kind{}; std::string destination, left, right; std::uint64_t target{}; };
struct FunctionIR { std::string name; std::vector<Operation> operations; };
inline std::string emitPseudoCode(const FunctionIR& fn) {
    std::ostringstream out; const auto name=fn.name.empty()?"sub_unknown":fn.name;
    out << "/* Pseudocode generated from decoded IR; not source reconstruction. */\nvoid " << name << "() {\n";
    for(const auto& op:fn.operations) {
        switch(op.kind) {
        case OpKind::Assign: out<<"    "<<op.destination<<" = "<<op.left<<";\n"; break;
        case OpKind::Add: out<<"    "<<op.destination<<" = "<<op.left<<" + "<<op.right<<";\n"; break;
        case OpKind::Subtract: out<<"    "<<op.destination<<" = "<<op.left<<" - "<<op.right<<";\n"; break;
        case OpKind::Compare: out<<"    /* compare "<<op.left<<" and "<<op.right<<" */\n"; break;
        case OpKind::Call: out<<"    "<<(op.destination.empty()?"call":op.destination)<<"("<<op.left<<");\n"; break;
        case OpKind::Return: out<<"    return"<<(op.left.empty()?"":" "+op.left)<<";\n"; break;
        case OpKind::Jump: out<<"    goto loc_"<<std::hex<<op.target<<std::dec<<";\n"; break;
        case OpKind::ConditionalJump: out<<"    if ("<<op.left<<") goto loc_"<<std::hex<<op.target<<std::dec<<";\n"; break;
        case OpKind::Comment: out<<"    /* "<<op.left<<" */\n"; break;
        }
    }
    out<<"}\n"; return out.str();
}
} // namespace lulz::decompiler
