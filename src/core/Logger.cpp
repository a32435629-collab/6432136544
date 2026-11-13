#include "lulz/core/Logger.hpp"
#include <iostream>
namespace lulz {
void log(LogLevel level, std::string_view message) {
    const char* tag = level == LogLevel::Info ? "INFO" :
                      level == LogLevel::Warning ? "WARN" : "ERROR";
    std::clog << '[' << tag << "] " << message << '\n';
}
}
