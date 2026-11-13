#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
namespace lulz::network {struct Endpoint{std::string host;std::uint16_t port;};std::optional<Endpoint> parseEndpoint(const std::string&s){auto p=s.rfind(':');if(p==s.npos||p==0||p+1==s.size())return {};unsigned n=0;auto v=std::string_view(s).substr(p+1);auto[e,ec]=std::from_chars(v.data(),v.data()+v.size(),n);if(ec!=std::errc{}||e!=v.data()+v.size()||n==0||n>65535)return {};return Endpoint{s.substr(0,p),static_cast<std::uint16_t>(n)};} }