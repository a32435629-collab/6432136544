# Function feature dataset

Version: 1.0

This directory contains a small, deterministic **synthetic starter dataset** for validating function-level feature ingestion. It is not a malware corpus and must not be used to claim real-world detection accuracy.

## Files

- `function_features.csv` — one function/binary observation per row.
- `schema.json` — column definitions, types, label meanings and provenance.

## CSV schema

The numeric feature columns mirror the current extractor naming where applicable:

- `imports.total`, `functions.total`
- `imports.dll_loading`, `imports.memory_operations`, `imports.network`, `imports.process`, `imports.crypto`
- `functions.average_size`, `functions.max_size`, `functions.with_no_decoded_instructions`
- `instructions.decoded_functions`, `instructions.total`, `instructions.calls`, `instructions.jumps`, `instructions.stack_operations`, `instructions.returns`

Categorical fields are `binary.format` and `binary.architecture`. The final `label` column is a synthetic teaching label: `benign_like` or `suspicious_like`.

## Important

Rows are hand-authored synthetic examples, not independently labeled executable samples. The label is intentionally coarse and does not establish that a binary is malicious. Normalize numeric columns and encode categorical columns in a separately versioned preprocessing pipeline before neural-network training. Keep train/test splits grouped by original binary to prevent leakage when adding real function-level rows.
