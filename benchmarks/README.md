# Benchmarks

A small, dependency-free microbenchmark for the repository's current feed-forward
neural network implementation.

## Build

Benchmarks are opt-in and are not part of normal builds:

```powershell
cmake -S . -B build -DDLL_LULZ_BUILD_TESTS=OFF -DDLL_LULZ_BUILD_BENCHMARKS=ON
cmake --build build --config Release --target lulz_neural_benchmark
.\build\Release\lulz_neural_benchmark.exe
```

For single-configuration generators, the executable is usually
`build/lulz_neural_benchmark.exe`.

## What it measures

- deterministic synthetic dataset generation (reported separately);
- training elapsed time and samples/second;
- inference elapsed time and samples/second;
- initial and final mean-squared-error loss.

The benchmark prints its workload and timings so results can be compared only
when compiler, build type, CPU, and workload match. Run several times and compare
medians. Close competing workloads and use a Release build.

## Limitations

This is a microbenchmark of the current in-process dense neural network, not a
full binary-analysis benchmark. It does not measure PE parsing, Zydis decoding,
feature extraction, end-to-end classification, GPU performance, or model
quality on real malware. The generated data is synthetic and must not be used
to claim detection accuracy. Timing output is informational; there are no
machine-specific pass/fail thresholds.
