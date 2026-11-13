#pragma once

#include <cstddef>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace lulz::ai::training {

struct TrainingSample {
    std::vector<double> inputs;
    std::vector<double> targets;
};

class Dataset {
public:
    bool addSample(std::vector<double> inputs, std::vector<double> targets,
                   std::string* error = nullptr);

    static std::optional<Dataset> loadCsv(
        std::istream& input,
        std::size_t targetColumns,
        bool hasHeader = true,
        char delimiter = ',',
        std::string* error = nullptr);

    std::size_t size() const noexcept;
    std::size_t featureCount() const noexcept;
    std::size_t targetCount() const noexcept;
    bool empty() const noexcept;
    const std::vector<TrainingSample>& samples() const noexcept;
    const std::vector<std::string>& featureNames() const noexcept;

private:
    std::vector<TrainingSample> samples_;
    std::vector<std::string> featureNames_;
    std::size_t featureCount_ = 0;
    std::size_t targetCount_ = 0;
};

} // namespace lulz::ai::training
