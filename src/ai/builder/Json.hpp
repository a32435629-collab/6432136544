#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace lulz::ai::builder {

struct JsonValue {
    using Array = std::vector<JsonValue>;
    using Object = std::map<std::string, JsonValue>;
    using Storage = std::variant<std::nullptr_t, bool, double, std::string, Array, Object>;

    Storage value = nullptr;

    bool isNull() const;
    bool isBool() const;
    bool isNumber() const;
    bool isString() const;
    bool isArray() const;
    bool isObject() const;

    const std::string* string() const;
    const Array* array() const;
    const Object* object() const;
    const JsonValue* get(const std::string& key) const;
};

struct JsonParseResult {
    bool success = false;
    JsonValue value;
    std::size_t errorOffset = 0;
    std::string error;
};

class JsonParser {
public:
    explicit JsonParser(std::string input);
    JsonParseResult parse();

private:
    std::string input_;
    std::size_t position_ = 0;
    std::size_t depth_ = 0;

    void skipWhitespace();
    bool consume(char expected);
    bool parseValue(JsonValue& out);
    bool parseObject(JsonValue& out);
    bool parseArray(JsonValue& out);
    bool parseString(std::string& out);
    bool parseNumber(double& out);
    bool parseLiteral(const char* literal);
    bool appendCodePoint(std::string& out, unsigned codePoint);
    bool fail(const std::string& message);
    std::string error_;
};

} // namespace lulz::ai::builder
