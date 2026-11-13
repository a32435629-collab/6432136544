#pragma once
#include <algorithm>
#include <cstdint>
#include <set>
#include <vector>
namespace lulz::reverse_engineering {
struct Instruction{std::uint64_t address=0;std::uint8_t size=0;bool isBranch=false,isConditional=false,isReturn=false;std::uint64_t target=0;};
struct BasicBlock{std::uint64_t start=0,end=0;std::vector<std::uint64_t> successors;};
struct Graph{std::vector<BasicBlock> blocks;};
inline Graph buildControlFlowGraph(std::vector<Instruction> ins){Graph g;if(ins.empty())return g;std::sort(ins.begin(),ins.end(),[](const auto&a,const auto&b){return a.address<b.address;});std::set<std::uint64_t> leaders{ins.front().address};for(std::size_t i=0;i<ins.size();++i){if(ins[i].isBranch)leaders.insert(ins[i].target);if((ins[i].isBranch||ins[i].isReturn)&&i+1<ins.size())leaders.insert(ins[i+1].address);}std::vector<std::size_t>s;for(std::size_t i=0;i<ins.size();++i)if(leaders.contains(ins[i].address))s.push_back(i);for(std::size_t b=0;b<s.size();++b){auto first=s[b],last=(b+1<s.size()?s[b+1]:ins.size())-1;BasicBlock x;x.start=ins[first].address;x.end=ins[last].address+ins[last].size;const auto&t=ins[last];auto exists=[&](std::uint64_t a){return std::any_of(ins.begin(),ins.end(),[&](const auto&i){return i.address==a;});};if(t.isBranch){if(exists(t.target))x.successors.push_back(t.target);if(t.isConditional&&last+1<ins.size())x.successors.push_back(ins[last+1].address);}else if(!t.isReturn&&last+1<ins.size())x.successors.push_back(ins[last+1].address);std::sort(x.successors.begin(),x.successors.end());x.successors.erase(std::unique(x.successors.begin(),x.successors.end()),x.successors.end());g.blocks.push_back(std::move(x));}return g;}
}