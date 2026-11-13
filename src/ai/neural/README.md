# Neural subsystem

Dependency-free CPU multilayer perceptron for DLL_LULZ_AI.

## Implemented

- Fully connected feed-forward networks with configurable topology.
- ReLU, tanh, sigmoid and linear activations.
- Deterministic Xavier-uniform initialization.
- Validated forward inference.
- Online stochastic-gradient descent with mean-squared-error loss.
- Optional deterministic sample shuffling.
- Versioned, portable little-endian model save/load.
- Defensive limits and validation for untrusted model files.

## Example

```cpp
#include "ai/neural/NeuralNetwork.hpp"
using namespace lulz::ai::neural;
NeuralNetwork model({2, 8, 1}, Activation::Tanh, Activation::Sigmoid, 42);
TrainingOptions options;
options.epochs = 2000;
options.learningRate = 0.1;
const std::vector<std::vector<double>> x{{0,0},{0,1},{1,0},{1,1}};
const std::vector<std::vector<double>> y{{0},{1},{1},{0}};
auto report = model.train(x, y, options);
auto prediction = model.predict({1,0});
```

## Model format and limitations

The model format stores a signature, version, topology, activation identifiers,
weights and biases in explicit little-endian encoding. The loader rejects unknown
versions, invalid dimensions, excessive parameter counts, non-finite parameters
and truncated streams. Model files are data and are never executed.

This is a compact MLP implementation, not a pretrained malware detector, LLM or
decompiler. Useful detection quality requires representative labeled data,
held-out evaluation and calibrated thresholds. No production detection accuracy
is claimed.
