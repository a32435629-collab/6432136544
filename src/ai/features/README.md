# AI Features 0.1.0

Feature extraction subsystem for DLL_LULZ_AI.

## Components

- Feature: individual feature representation.
- FeatureVector: collection of extracted features.
- FeatureExtractor: main extraction interface.
- ImportFeatures: import-related statistics.
- FunctionFeatures: function statistics.
- InstructionFeatures: instruction-related statistics.

## Input

AIContext from AI Core.

## Output

FeatureVector containing numeric, categorical and boolean features.

## Status

Version: 0.1.0

- Basic feature representation: implemented
- Import features: implemented
- Function features: implemented
- Instruction features: implemented
- Neural model integration: planned