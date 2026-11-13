#include "Dataset.hpp"

#include <cmath>
#include <cstdlib>
#include <utility>

namespace lulz::ai::training {
namespace {

void setError(std::string* error, const char* message) {
    if (error) *error = message;
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseRow(const std::string& line, char delimiter,
              std::vector<std::string>& fields) {
    fields.clear();
    std::string field;
    bool quoted = false;
    bool closedQuote = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (quoted) {
            if (ch == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    field.push_back('"');
                    ++i;
                } else {
                    quoted = false;
                    closedQuote = true;
                }
            } else {
                field.push_back(ch);
            }
        } else if (ch == delimiter) {
            fields.push_back(trim(std::move(field)));
            field.clear();
            closedQuote = false;
        } else if (ch == '"' && trim(field).empty() && !closedQuote) {
            field.clear();
            quoted = true;
        } else {
            if (closedQuote && ch != ' ' && ch != '\t' && ch != '\r') return false;
            field.push_back(ch);
        }
    }
    if (quoted) return false;
    fields.push_back(trim(std::move(field)));
    return true;
}

bool parseNumber(const std::string& field, double& value) {
    if (field.empty()) return false;
    char* end = nullptr;
    value = std::strtod(field.c_str(), &end);
    return end != field.c_str() && *end == '\0' && std::isfinite(value);
}

} // namespace

bool Dataset::addSample(std::vector<double> inputs,
                        std::vector<double> targets,
                        std::string* error) {
    if (inputs.empty() || targets.empty()) {
        setError(error, "Each sample must contain at least one input and one target");
        return false;
    }
    for (double value : inputs) {
        if (!std::isfinite(value)) {
            setError(error, "Sample inputs must be finite numbers");
            return false;
        }
    }
    for (double value : targets) {
        if (!std::isfinite(value)) {
            setError(error, "Sample targets must be finite numbers");
            return false;
        }
    }
    if (samples_.empty()) {
        featureCount_ = inputs.size();
        targetCount_ = targets.size();
    } else if (inputs.size() != featureCount_ || targets.size() != targetCount_) {
        setError(error, "Sample dimensions do not match the existing dataset");
        return false;
    }
    samples_.push_back({std::move(inputs), std::move(targets)});
    return true;
}

std::optional<Dataset> Dataset::loadCsv(std::istream& input,
                                        std::size_t targetColumns,
                                        bool hasHeader,
                                        char delimiter,
                                        std::string* error) {
    if (targetColumns == 0 || delimiter == '"' || delimiter == '\n' ||
        delimiter == '\r') {
        setError(error, "CSV target column count or delimiter is invalid");
        return std::nullopt;
    }

    Dataset dataset;
    std::string line;
    std::vector<std::string> fields;
    bool headerPending = hasHeader;

    while (std::getline(input, line)) {
        if (trim(line).empty()) continue;
        if (!parseRow(line, delimiter, fields)) {
            setError(error, "Malformed quoted CSV row");
            return std::nullopt;
        }
        if (fields.size() <= targetColumns) {
            setError(error, "CSV row has too few columns");
            return std::nullopt;
        }
        if (headerPending) {
            const auto featureColumns = fields.size() - targetColumns;
            dataset.featureNames_.assign(fields.begin(),
                fields.begin() + static_cast<std::ptrdiff_t>(featureColumns));
            for (const auto& name : dataset.featureNames_) {
                if (name.empty()) {
                    setError(error, "CSV feature header contains an empty name");
                    return std::nullopt;
                }
            }
            headerPending = false;
            continue;
        }

        const auto featureColumns = fields.size() - targetColumns;
        if (!dataset.samples_.empty() && featureColumns != dataset.featureCount_) {
            setError(error, "CSV rows have inconsistent column counts");
            return std::nullopt;
        }
        std::vector<double> inputs;
        std::vector<double> targets;
        inputs.reserve(featureColumns);
        targets.reserve(targetColumns);
        for (std::size_t i = 0; i < fields.size(); ++i) {
            double value = 0.0;
            if (!parseNumber(fields[i], value)) {
                setError(error, "CSV contains an empty, non-numeric, or non-finite value");
                return std::nullopt;
            }
            (i < featureColumns ? inputs : targets).push_back(value);
        }
        if (!dataset.addSample(std::move(inputs), std::move(targets), error)) {
            return std::nullopt;
        }
    }

    if (input.bad() || dataset.empty()) {
        setError(error, "CSV input failed or contains no training samples");
        return std::nullopt;
    }
    if (!dataset.featureNames_.empty() &&
        dataset.featureNames_.size() != dataset.featureCount_) {
        setError(error, "CSV header and data column counts do not match");
        return std::nullopt;
    }
    return dataset;
}

std::size_t Dataset::size() const noexcept { return samples_.size(); }
std::size_t Dataset::featureCount() const noexcept { return featureCount_; }
std::size_t Dataset::targetCount() const noexcept { return targetCount_; }
bool Dataset::empty() const noexcept { return samples_.empty(); }
const std::vector<TrainingSample>& Dataset::samples() const noexcept { return samples_; }
const std::vector<std::string>& Dataset::featureNames() const noexcept { return featureNames_; }

} // namespace lulz::ai::training
