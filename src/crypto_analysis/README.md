# Crypto analysis

Header-only static byte-analysis helpers in `CryptoAnalysis.hpp`.

Includes byte frequencies, Shannon entropy, printable-byte ratio, repeated fixed-size block discovery, and ranked single-byte XOR candidates. These are heuristics for triage only: entropy or printable scores do not prove encryption, identify an algorithm, or establish maliciousness.
