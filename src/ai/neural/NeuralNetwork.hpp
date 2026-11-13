#pragma once
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>
namespace lulz::ai::neural {
enum class Activation : std::uint8_t { Linear=0, Relu=1, Tanh=2, Sigmoid=3 };
struct TrainingOptions { std::size_t epochs=100; double learningRate=0.01; bool shuffle=true; std::uint32_t seed=0x4c554c5a; };
struct TrainingReport { std::size_t epochsCompleted=0; double initialLoss=0.0; double finalLoss=0.0; };
class NeuralNetwork {
public:
 explicit NeuralNetwork(std::vector<std::size_t> topology, Activation hiddenActivation=Activation::Relu, Activation outputActivation=Activation::Linear, std::uint32_t seed=0x4c554c5a);
 bool valid() const noexcept;
 std::size_t inputSize() const noexcept;
 std::size_t outputSize() const noexcept;
 const std::vector<std::size_t>& topology() const noexcept;
 std::optional<std::vector<double>> predict(const std::vector<double>& input, std::string* error=nullptr) const;
 std::optional<TrainingReport> train(const std::vector<std::vector<double>>& inputs, const std::vector<std::vector<double>>& targets, const TrainingOptions& options={}, std::string* error=nullptr);
 bool save(std::ostream& output, std::string* error=nullptr) const;
 static std::optional<NeuralNetwork> load(std::istream& input, std::string* error=nullptr);
private:
 struct Layer { std::size_t inputCount=0, outputCount=0; Activation activation=Activation::Linear; std::vector<double> weights, biases; };
 std::vector<std::size_t> topology_;
 std::vector<Layer> layers_;
 static double activate(double value, Activation activation) noexcept;
 static double derivative(double activated, Activation activation) noexcept;
 std::optional<std::vector<double>> forward(const std::vector<double>& input, std::vector<std::vector<double>>* activations, std::string* error) const;
 double loss(const std::vector<std::vector<double>>& inputs, const std::vector<std::vector<double>>& targets) const;
};
} // namespace lulz::ai::neural
