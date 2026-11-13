#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
namespace lulz::decompiler { struct DecodedInstruction{std::uint64_t address{};std::string mnemonic,operands;bool valid{true};};std::vector<std::string> listing(const std::vector<DecodedInstruction>&v){std::vector<std::string>o;for(const auto&i:v){std::ostringstream s;s<<"0x"<<std::hex<<i.address<<": ";if(!i.valid)s<<"<invalid>";else{s<<i.mnemonic;if(!i.operands.empty())s<<" "<<i.operands;}o.push_back(s.str());}return o;} }