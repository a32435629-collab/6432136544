# ELF parser

This directory contains a bounds-checked ELF parser for ELF32 and ELF64 images.

## Supported

- Little-endian and big-endian byte order
- ELF identification and main header metadata
- Program headers and segment metadata
- Interpreter path from `PT_INTERP`
- Section headers and section names
- Dynamic dependencies from `SHT_DYNAMIC` / `DT_NEEDED`
- Extended section count, program-header count, and section-name table index

The parser rejects truncated tables and file-backed ranges outside the input buffer. It does not yet decode symbol tables, relocations, notes, GNU version metadata, or compressed sections.
