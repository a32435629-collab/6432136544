# AI configuration presets

This directory contains versioned JSON presets for the current `lulz::ai::AIConfig`
limits and provider metadata.

## Files

- `ai.default.json` — conservative defaults.
- `ai.fast.json` — smaller analysis limits for quick interactive runs.
- `ai.deep.json` — larger bounded limits for offline analysis.
- `schema.json` — JSON Schema (Draft 2020-12) for these files.

## Important integration note

The current `AIConfig` C++ type validates limits but does not load JSON files.
These presets are documented configuration data, not automatically applied at
startup. A JSON parser/loader and CLI selection are separate future work.
The `provider`, `modelName`, and `endpoint` fields are metadata only; they do
not establish a network connection or enable an external AI provider.

Keep limits within the bounds enforced by `AIConfig::validate()`. Do not put
API keys, passwords, or other secrets in these files. Use environment variables
or an OS-protected secret store if provider credentials are added later.
