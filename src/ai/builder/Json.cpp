#include "ai/builder/Json.hpp"

#include <cmath>
#include <cstdlib>
#include <utility>
#include <cstdlib>
#include <limits>

namespace lulz::ai::builder {

bool JsonValue::isNull() const { return std::holds_alternative<std::nullptr_t>(value); }
bool JsonValue::isBool() const { return std::holds_alternative<bool>(value); }
bool JsonValue::isNumber() const { return std::holds_alternative<double>(value); }
bool JsonValue::isString() const { return std::holds_alternative<std::string>(value); }
bool JsonValue::isArray() const { return std::holds_alternative<Array>(value); }
bool JsonValue::isObject() const { return std::holds_alternative<Object>(value); }
const std::string* JsonValue::string() const { return std::get_if<std::string>(&value); }
const JsonValue::Array* JsonValue::array() const { return std::get_if<Array>(&value); }
const JsonValue::Object* JsonValue::object() const { return std::get_if<Object>(&value); }
const JsonValue* JsonValue::get(const std::string& key) const {
    const auto* values = object();
    if (!values) return nullptr;
    const auto found = values->find(key);
    return found == values->end() ? nullptr : &found->second;
}

JsonParser::JsonParser(std::string input) : input_(std::move(input)) {}

void JsonParser::skipWhitespace() {
    while (position_ < input_.size()) {
        const char c = input_[position_];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++position_;
    }
}

bool JsonParser::consume(char expected) {
    skipWhitespace();
    if (position_ >= input_.size() || input_[position_] != expected) return false;
    ++position_;
    return true;
}

bool JsonParser::fail(const std::string& message) {
    if (error_.empty()) error_ = message;
    return false;
}

bool JsonParser::appendCodePoint(std::string& out, unsigned cp) {
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return fail("invalid Unicode code point");
    if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
    return true;
}

bool JsonParser::parseString(std::string& out) {
    if (!consume('"')) return fail("expected string");
    while (position_ < input_.size()) {
        const unsigned char c = static_cast<unsigned char>(input_[position_++]);
        if (c == '"') return true;
        if (c < 0x20) return fail("unescaped control character in string");
        if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
        if (position_ >= input_.size()) return fail("truncated escape sequence");
        const char escaped = input_[position_++];
        switch (escaped) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
            auto readHex = [&]() -> int {
                if (position_ + 4 > input_.size()) return -1;
                unsigned value = 0;
                for (int i = 0; i < 4; ++i) {
                    const char h = input_[position_++];
                    value <<= 4;
                    if (h >= '0' && h <= '9') value |= unsigned(h - '0');
                    else if (h >= 'a' && h <= 'f') value |= unsigned(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') value |= unsigned(h - 'A' + 10);
                    else return -1;
                }
                return static_cast<int>(value);
            };
            const int first = readHex();
            if (first < 0) return fail("invalid Unicode escape");
            unsigned cp = static_cast<unsigned>(first);
            if (cp >= 0xd800 && cp <= 0xdbff) {
                if (position_ + 2 > input_.size() || input_[position_] != '\\' || input_[position_ + 1] != 'u')
                    return fail("missing low surrogate");
                position_ += 2;
                const int second = readHex();
                if (second < 0 || second < 0xdc00 || second > 0xdfff) return fail("invalid low surrogate");
                cp = 0x10000 + ((cp - 0xd800) << 10) + (unsigned(second) - 0xdc00);
            }
            if (!appendCodePoint(out, cp)) return false;
            break;
        }
        default: return fail("unknown string escape");
        }
    }
    return fail("unterminated string");
}

bool JsonParser::parseNumber(double& out) {
    skipWhitespace();
    const std::size_t start = position_;
    if (position_ < input_.size() && input_[position_] == '-') ++position_;
    if (position_ >= input_.size()) return fail("incomplete number");
    if (input_[position_] == '0') ++position_;
    else {
        if (input_[position_] < '1' || input_[position_] > '9') return fail("invalid number");
        while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
    }
    if (position_ < input_.size() && input_[position_] == '.') {
        ++position_;
        const auto fraction = position_;
        while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
        if (fraction == position_) return fail("fraction has no digits");
    }
    if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
        ++position_;
        if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) ++position_;
        const auto exponent = position_;
        while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
        if (exponent == position_) return fail("exponent has no digits");
    }
    const std::string token = input_.substr(start, position_ - start);
    char* end = nullptr;
    out = std::strtod(token.c_str(), &end);
    if (!end || *end != '\0' || !std::isfinite(out)) return fail("number is out of range");
    return true;
}

bool JsonParser::parseLiteral(const char* literal) {
    const std::string token(literal);
    if (input_.compare(position_, token.size(), token) != 0) return false;
    position_ += token.size();
    return true;
}

bool JsonParser::parseArray(JsonValue& out) {
    if (!consume('[')) return fail("expected '['");
    JsonValue::Array values;
    skipWhitespace();
    if (consume(']')) { out.value = std::move(values); return true; }
    while (true) {
        JsonValue item;
        if (!parseValue(item)) return false;
        values.push_back(std::move(item));
        if (consume(']')) break;
        if (!consume(',')) return fail("expected ',' or ']'");
    }
    out.value = std::move(values);
    return true;
}

bool JsonParser::parseObject(JsonValue& out) {
    if (!consume('{')) return fail("expected '{'");
    JsonValue::Object values;
    skipWhitespace();
    if (consume('}')) { out.value = std::move(values); return true; }
    while (true) {
        std::string key;
        if (!parseString(key)) return false;
        if (!consume(':')) return fail("expected ':' after object key");
        JsonValue item;
        if (!parseValue(item)) return false;
        if (!values.emplace(std::move(key), std::move(item)).second)
            return fail("duplicate object key");
        if (consume('}')) break;
        if (!consume(',')) return fail("expected ',' or '}'");
    }
    out.value = std::move(values);
    return true;
}

bool JsonParser::parseValue(JsonValue& out) {
    skipWhitespace();
    if (++depth_ > 128) { --depth_; return fail("maximum JSON nesting depth exceeded"); }
    bool ok = false;
    if (position_ >= input_.size()) ok = fail("unexpected end of input");
    else {
        const char c = input_[position_];
        if (c == '{') ok = parseObject(out);
        else if (c == '[') ok = parseArray(out);
        else if (c == '"') { std::string s; ok = parseString(s); if (ok) out.value = std::move(s); }
        else if (c == 't' && parseLiteral("true")) { out.value = true; ok = true; }
        else if (c == 'f' && parseLiteral("false")) { out.value = false; ok = true; }
        else if (c == 'n' && parseLiteral("null")) { out.value = nullptr; ok = true; }
        else { double n = 0; ok = parseNumber(n); if (ok) out.value = n; }
    }
    --depth_;
    return ok;
}

JsonParseResult JsonParser::parse() {
    JsonParseResult result;
    if (!parseValue(result.value)) {
        result.error = error_.empty() ? "invalid JSON" : error_;
        result.errorOffset = position_;
        return result;
    }
    skipWhitespace();
    if (position_ != input_.size()) {
        result.error = "unexpected trailing characters";
        result.errorOffset = position_;
        return result;
    }
    result.success = true;
    return result;
}

} // namespace lulz::ai::builder
