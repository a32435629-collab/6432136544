# AI Features 0.2.0

Feature extraction subsystem for DLL_LULZ_AI. All features are deterministic static indicators.

## Feature groups
- Binary: format, architecture, import/function/instruction totals.
- Imports: dynamic API resolution, memory and remote-memory operations, network, process, crypto, persistence, anti-analysis, and selected ratios.
- Functions: decoded/undecoded counts, decoded ratio, average/minimum/maximum instruction count, empty decoded functions.
- Instructions: calls, jumps, stack operations, returns, control-flow total, and unparsed text count.

Import matching is case-insensitive. Instruction classification uses the mnemonic token rather than broad string-prefix checks.

## Limitations
The extractor consumes import names and assembly text already supplied in AIContext. It does not independently disassemble binaries, and its indicators do not establish malicious intent. Neural model integration/training remains separate.
