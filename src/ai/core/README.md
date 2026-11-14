# AI Core 0.2.0

AI Core validates analysis input, enforces configurable resource limits, extracts a structured feature vector, and returns a deterministic static-analysis summary.

## Current behavior
- Validates AIConfig and AIContext before processing.
- Defaults to a 5,000-function limit, with configurable import and instruction limits.
- Runs FeatureExtractor as part of every successful analysis.
- Reports static heuristic indicators for dynamic API resolution, remote memory, persistence, anti-analysis, and decoded control flow.
- Preserves extracted features in AIAnalysisResult for downstream consumers.

## Important limitations
- Local/OpenAI provider values are configuration metadata; network provider integration is not implemented here.
- No trained malware classifier is invoked. Findings are explainable static indicators, not verdicts.
