#pragma once
#include "lulz/core/Result.hpp"
#include <cctype>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>
namespace lulz::scripting {
using Handler=std::function<Result<std::string>(const std::vector<std::string>&)>;
class CommandEngine{std::unordered_map<std::string,Handler> handlers_;public:
 Result<bool> registerCommand(std::string n,Handler h){if(n.empty()||!h)return Result<bool>::failure("Command name and handler are required");for(unsigned char c:n)if(!(std::isalnum(c)||c=='_'||c=='-'))return Result<bool>::failure("Invalid command name");if(handlers_.contains(n))return Result<bool>::failure("Command already registered");handlers_.emplace(std::move(n),std::move(h));return Result<bool>::success(true);}
 Result<std::string> execute(const std::string&line)const{std::vector<std::string>t;std::string cur;bool q=false,e=false,a=false;for(char c:line){if(e){cur+=c;e=false;a=true;continue;}if(c=='\\'&&q){e=true;continue;}if(c=='"'){q=!q;a=true;continue;}if(std::isspace(static_cast<unsigned char>(c))&&!q){if(a){t.push_back(cur);cur.clear();a=false;}continue;}cur+=c;a=true;}if(q||e)return Result<std::string>::failure("Unterminated quoted argument");if(a)t.push_back(cur);if(t.empty())return Result<std::string>::failure("Empty command");auto i=handlers_.find(t.front());if(i==handlers_.end())return Result<std::string>::failure("Unknown command: "+t.front());t.erase(t.begin());return i->second(t);}
};
}