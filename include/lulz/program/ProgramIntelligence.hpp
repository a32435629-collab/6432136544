#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
namespace lulz::program {
struct Component { std::string id,name,kind; bool entry=false, initializer=false, finalizer=false; };
struct Dependency { std::string from,to; };
struct Model {
 std::vector<Component> components; std::vector<Dependency> dependencies;
};
struct Report {
 std::vector<std::string> entryPoints, initializationOrder, shutdownOrder, cycles, components;
 std::unordered_map<std::string,std::size_t> incoming,outgoing;
 std::size_t dependencyCount=0;
 bool acyclic=true;
 std::string toJson() const;
};
Report analyze(const Model& model);
}
