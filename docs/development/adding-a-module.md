# Adding a module
1. Define a narrow public API under `include/lulz/<module>/`.
2. Implement it under `src/<module>/`.
3. Validate all offsets and lengths before reading.
4. Add unit tests for normal, truncated and malformed inputs.
5. Add the source to `lulz_core` in CMakeLists.txt.
6. Document supported formats and limitations.
