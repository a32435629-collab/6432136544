# Decompiler

`IR.hpp` defines a small intermediate-operation model and a deterministic pseudocode emitter.

The emitter consumes already-decoded/normalized IR. It is not a machine-code decompiler and does not recover types, control structures, variables, or original source semantics.
