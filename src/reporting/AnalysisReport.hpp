#pragma once
#include <sstream>
#include <string>
#include <vector>
namespace lulz::reporting {
struct Finding{std::string severity,title,description,location;};
struct Report{std::string fileName,format,sha256;std::vector<Finding> findings;};
inline std::string escapeJson(const std::string&s){std::string o;for(unsigned char c:s)switch(c){case '"':o+="\\\"";break;case '\\':o+="\\\\";break;case '\n':o+="\\n";break;case '\r':o+="\\r";break;case '\t':o+="\\t";break;default:if(c<0x20)o+=' ';else o+=static_cast<char>(c);}return o;}
inline std::string toJson(const Report&r){std::ostringstream o;o<<"{\n \"file\": \""<<escapeJson(r.fileName)<<"\",\n \"format\": \""<<escapeJson(r.format)<<"\",\n \"sha256\": \""<<escapeJson(r.sha256)<<"\",\n \"findings\": [";for(std::size_t i=0;i<r.findings.size();++i){const auto&f=r.findings[i];o<<(i?",":"")<<"\n  {\"severity\":\""<<escapeJson(f.severity)<<"\",\"title\":\""<<escapeJson(f.title)<<"\",\"description\":\""<<escapeJson(f.description)<<"\",\"location\":\""<<escapeJson(f.location)<<"\"}";}o<<"\n ]\n}\n";return o.str();}
inline std::string toMarkdown(const Report&r){std::ostringstream o;o<<"# Analysis report\n\n- **File:** "<<r.fileName<<"\n- **Format:** "<<r.format<<"\n- **SHA-256:** "<<r.sha256<<"\n\n## Findings\n";if(r.findings.empty())o<<"\nNo findings recorded.\n";for(const auto&f:r.findings)o<<"\n### ["<<f.severity<<"] "<<f.title<<"\n\n"<<f.description<<"\n\n- Location: "<<f.location<<"\n";return o.str();}
}