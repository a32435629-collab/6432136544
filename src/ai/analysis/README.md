# AI Analysis 0.2.0

AI Analysis orchestrates AI Core and preserves its structured output.

## Pipeline
AnalysisInput -> AIAnalyzer -> AIEngine -> AnalysisResult -> AnalysisReport

## Current behavior
- Validates and forwards AIContext.
- Carries the extracted FeatureVector through AnalysisResult.
- Collects static heuristic findings and errors.
- Generates text reports including feature names and values.

No trained-model inference or external AI provider request is performed by this layer.
