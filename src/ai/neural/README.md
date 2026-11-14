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


## DLL LULZ AI 0.6.0 integration

The AI engine can run a local checkpoint with:

```powershell
dll_lulz.exe ai sample.exe --model models/checkpoints/model.lznn
```

The checkpoint must be trained for the exact numeric feature-vector schema and
feature order emitted by the matching application version. The loader validates
the model file and the inference input dimension. No pretrained malware model is
bundled, and a successful forward pass is not evidence of malware-detection
accuracy. OpenAI requests are sent over HTTPS on Windows using WinHTTP. The API key is read from the OPENAI_API_KEY environment variable; original file bytes are not uploaded.


### OpenAI provider

On Windows, run:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
dll_lulz.exe ai sample.exe --openai
```

The default model is `gpt-4o-mini`. Only extracted static feature metadata is
sent to the endpoint; the original executable bytes are not uploaded. A custom
endpoint can be set through `AIConfig::endpoint`.
