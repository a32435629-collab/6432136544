# DLL LULZ AI v0.5.0

A modular C++20 reverse-engineering and binary-analysis workbench.

## Current implementation (v0.1 foundation)

Implemented and usable:
- binary file loading and bounded little-endian reads;
- hex text parsing and formatting;
- basic file-format identification;
- PE32/PE32+ header and section-table inspection;
- byte-frequency entropy estimate;
- small, explicitly limited x86/x64 instruction decoder and encoder;
- heuristic function-entry candidate finder;
- x64 PE exception-directory (`.pdata`) and `UNWIND_INFO` parsing, including common `UWOP_*` operations, chained records, and handler metadata;
- human-readable and JSON unwind output;
- command-line interface and unit tests for normal and malformed unwind records.

Not yet implemented: a complete x86/x64/ARM64 assembler, production-grade disassembler,
full decompiler, debugger, process-memory editing, packet capture, .NET metadata reader,
or a trained AI model. Those are planned modules, not falsely advertised as finished.

## Build (Windows)

Install CMake and a C++20 compiler (Visual Studio 2022 or recent MinGW-w64).

```powershell
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Run:
```powershell
.\build\Release\dll_lulz.exe info .\sample.exe
.\build\Release\dll_lulz.exe hex .\sample.dll
.\build\Release\dll_lulz.exe disasm 4889D84883C001C3
.\build\Release\dll_lulz.exe pe .\sample.exe
.\build\Release\dll_lulz.exe unwind .\sample.exe
.\build\Release\dll_lulz.exe unwind .\sample.exe --json
```

For single-config generators (e.g. MinGW Makefiles), executable is usually `build/dll_lulz.exe`.

## Safety

Treat unknown binaries as untrusted data. This program parses files without executing them.
Use isolated test environments for dynamic analysis. Keep original samples immutable and
record their SHA-256 with a trusted hashing utility.

## Roadmap

1. Expand instruction coverage and add architecture backends.
2. Add CFG and function analysis.
3. Add robust PE/ELF/Mach-O and .NET readers.
4. Add debugger adapters and safe dump inspection.
5. Add network capture-file parsing.
6. Build a compact, locally trained classifier with measured accuracy and resource budgets.


## Function Analysis Engine (v0.5)

The x64 PE analyzer combines `.pdata` `RUNTIME_FUNCTION` ranges with parsed `UNWIND_INFO`, saved GPR/XMM registers, stack-frame sizes, and bounded `CHAININFO` traversal. It also parses PE imports and builds a call graph from x64 instructions decoded by Zydis, including relative CALL/JMP and RIP-relative IAT forms.

```powershell
.\build\Release\dll_lulz.exe analyze "C:\Windows\System32\notepad.exe"
.\build\Release\dll_lulz.exe analyze "C:\Windows\System32\notepad.exe" --json report.json
```

Call-site discovery uses Zydis instruction boundaries, avoiding opcode-like bytes inside immediates and displacements. Indirect targets outside supported RIP-relative IAT slots remain unresolved. The module currently targets x64 PE32+ images with `.pdata`; other architectures and complete instruction decoding are future work.


## Validation status

The x64 PE call-site scan uses Zydis decoding but remains a best-effort control-flow graph: indirect targets and exceptional control-flow edges may remain unresolved. AI feature extraction counts instruction-derived metrics only for functions explicitly marked as decoded; metadata summaries are not instructions. The current AI engine is a rules/statistics scaffold and does not run a trained neural model.

Release test builds explicitly keep assertions enabled. The repository CI workflow builds and runs tests on Windows and Ubuntu.
