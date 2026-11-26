#include "lulz/program/ProgramIntelligence.hpp"
#include <cassert>
#include <iostream>
using namespace lulz::program;
int main(){Model m; m.components={{"app","App","exe",true,false,false},{"core","Core","lib",false,true,false},{"ui","UI","lib",false,false,true}};m.dependencies={{"app","core"},{"core","ui"}};auto r=analyze(m);assert(r.acyclic&&r.components.size()==3&&r.dependencyCount==2);assert(r.initializationOrder.front()=="app");assert(r.shutdownOrder.front()=="ui");assert(r.entryPoints.size()==1);Model c;c.components={{"x","x","",false,false,false},{"y","y","",false,false,false}};c.dependencies={{"x","y"},{"y","x"}};auto cr=analyze(c);assert(!cr.acyclic&&cr.cycles.size()==2);assert(!r.toJson().empty());std::cout<<"program intelligence tests passed\\n";}