#include "lulz/program/ProgramIntelligence.hpp"
#include <algorithm>
#include <sstream>
#include <queue>
#include <unordered_set>
namespace lulz::program {
namespace {
std::string quote(const std::string& s){std::string o="\"";for(char c:s){if(c=='\\'||c=='\"')o+='\\';if(c=='\n')o+="\\n";else o+=c;}return o+"\"";}
}
Report analyze(const Model& m){
 Report r; r.components.reserve(m.components.size()); std::unordered_map<std::string,const Component*> nodes;
 for(const auto& c:m.components){if(c.id.empty()||nodes.contains(c.id))continue;nodes[c.id]=&c;r.components.push_back(c.id);r.incoming[c.id]=0;r.outgoing[c.id]=0;if(c.entry)r.entryPoints.push_back(c.id);}
 std::unordered_map<std::string,std::vector<std::string>> adj,rev;std::unordered_map<std::string,std::size_t> indeg;
 for(const auto& id:r.components)indeg[id]=0;
 for(const auto& e:m.dependencies){if(!nodes.contains(e.from)||!nodes.contains(e.to)||e.from==e.to)continue;adj[e.from].push_back(e.to);rev[e.to].push_back(e.from);++indeg[e.to];++r.outgoing[e.from];++r.incoming[e.to];++r.dependencyCount;}
 std::queue<std::string> q;for(const auto& id:r.components)if(indeg[id]==0)q.push(id);
 while(!q.empty()){auto id=q.front();q.pop();r.initializationOrder.push_back(id);for(auto& n:adj[id])if(--indeg[n]==0)q.push(n);}
 r.acyclic=r.initializationOrder.size()==r.components.size();
 if(!r.acyclic)for(const auto& id:r.components)if(indeg[id])r.cycles.push_back(id);
 if(r.acyclic){for(auto it=r.initializationOrder.rbegin();it!=r.initializationOrder.rend();++it)r.shutdownOrder.push_back(*it);}
 else {for(const auto& id:r.components)r.shutdownOrder.push_back(id);std::reverse(r.shutdownOrder.begin(),r.shutdownOrder.end());}
 return r;
}
std::string Report::toJson() const{
 std::ostringstream o;o<<"{\"component_count\":"<<components.size()<<",\"dependency_count\":"<<dependencyCount<<",\"acyclic\":"<<(acyclic?"true":"false")<<",\"entry_points\":[";
 for(size_t i=0;i<entryPoints.size();++i){if(i)o<<',';o<<quote(entryPoints[i]);}
 auto arr=[&](const char* key,const std::vector<std::string>& v){o<<"],\""<<key<<"\":[";for(size_t i=0;i<v.size();++i){if(i)o<<',';o<<quote(v[i]);}};
 arr("initialization_order",initializationOrder);arr("shutdown_order",shutdownOrder);arr("cycle_nodes",cycles);o<<"],\"degree\":{";size_t i=0;for(const auto& id:components){if(i++)o<<',';o<<quote(id)<<":{\"in\":"<<incoming.at(id)<<",\"out\":"<<outgoing.at(id)<<"}";}o<<"}}";return o.str();
}
}
