# AI training subsystem

A dependency-free supervised-training pipeline built on the CPU multilayer
perceptron in `ai/neural/NeuralNetwork.hpp`.

## Components

- `Dataset` stores finite numeric input/target vectors and enforces consistent
  dimensions for every sample.
- The CSV loader supports an optional header, configurable delimiter, quoted
  fields and escaped quotes. It rejects malformed rows, missing values,
  non-numeric values and infinities/NaNs.
- `Trainer` creates a deterministic shuffled train/validation split, trains
  the supplied network with SGD and reports sample counts plus mean-squared
  error (MSE) on both partitions.

The last `targetColumns` columns of each CSV row are targets; preceding
columns are input features. Header names for input features are retained.

## Example

```cpp
#include "ai/neural/NeuralNetwork.hpp"
#include "ai/training/Dataset.hpp"
#include "ai/training/Trainer.hpp"

#include <fstream>

using namespace lulz::ai::neural;
using namespace lulz::ai::training;

std::ifstream file("training.csv");
auto dataset = Dataset::loadCsv(file, 1); // last column is the target
if (dataset) {
    NeuralNetwork model({dataset->featureCount(), 8, dataset->targetCount()},
                        Activation::Relu, Activation::Sigmoid);
    TrainerOptions options;
    options.network.epochs = 1000;
    options.network.learningRate = 0.02;
    options.validationFraction = 0.2;

    auto report = Trainer::train(model, *dataset, options);
}
```

## Limitations

Only numeric labeled data is supported. This module does not download samples,
execute binaries, infer labels, or include a pretrained malware classifier.
Validation MSE is diagnostic, not proof of detection quality. Use representative
labeled samples and a separate held-out evaluation set; prevent related files
from leaking across splits. Scale features consistently when their magnitudes
differ substantially.
