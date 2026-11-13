# Assembly sequence dataset

Version: 1.0

This directory provides labeled x86/x86-64 **synthetic instruction snippets** for testing assembly-token parsing and sequence ingestion.

## Files

- `instruction_sequences.csv` — short instruction sequences with illustrative labels.
- `schema.json` — field definitions and label semantics.

The `instructions` field uses instructions separated by semicolons. Values are mnemonic-plus-operands text, not guaranteed byte-for-byte disassembly output. The current project decoder is not a full instruction coverage implementation, so unsupported encodings must remain explicitly unsupported.

## Labels and limitations

- `benign_like`: ordinary arithmetic, stack-frame, comparison, return, and call patterns.
- `suspicious_like`: patterns often worth reviewing, such as dynamic API resolution, executable-memory permission changes, process-memory access, or indirect control transfer.

These are heuristic educational labels, not proof of malicious intent. Legitimate software, debuggers, JITs, installers, and security tools may contain the same operations. The dataset is synthetic, small, and unsuitable for accuracy claims or production model training.
