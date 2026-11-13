# Binary diff

`BinaryDiff.hpp` compares two byte spans and reports contiguous changed ranges, equal-byte counts, and size differences.

The comparison is offset-based (not semantic, function-aware, or relocation-aware). It performs no file I/O.
