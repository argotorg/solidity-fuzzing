# AFL Fuzzers

## Executables generated

- `solfuzzer` (from `solfuzzer.cpp`). AFL-based fuzzer that reads Solidity
  source from stdin or a file, compiles it, and signals a failure on internal
  errors. Supports `--standard-json` (test via JSON interface), `--const-opt`
  (test the constant optimizer), and `--without-optimizer` modes. Built by
  the normal (non-ossfuzz) cmake build.
