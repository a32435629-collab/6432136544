#pragma once
#include <string>
#include <utility>
#include <variant>

namespace lulz {
template<class T>
class Result {
public:
    static Result success(T value) { return Result(std::move(value)); }
    static Result failure(std::string error) { return Result(std::move(error)); }
    bool ok() const noexcept { return std::holds_alternative<T>(data_); }
    explicit operator bool() const noexcept { return ok(); }
    const T& value() const { return std::get<T>(data_); }
    T& value() { return std::get<T>(data_); }
    const std::string& error() const { return std::get<std::string>(data_); }
private:
    explicit Result(T value) : data_(std::move(value)) {}
    explicit Result(std::string error) : data_(std::move(error)) {}
    std::variant<T, std::string> data_;
};
}
