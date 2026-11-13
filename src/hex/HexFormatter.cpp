#include "lulz/hex/HexParser.hpp"
#include <iomanip>
#include <sstream>
namespace lulz {
std::string formatHex(const std::vector<std::uint8_t>& b, std::size_t columns) {
    std::ostringstream o; o << std::hex << std::setfill('0');
    for (std::size_t i=0;i<b.size();++i) {
        if (i%columns==0) { if(i) o << '\n'; o << std::setw(8) << i << "  "; }
        o << std::setw(2) << static_cast<unsigned>(b[i]) << ' ';
    }
    return o.str();
}
}
