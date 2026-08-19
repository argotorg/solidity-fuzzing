# Solidity Fuzzing Tools

Fuzzing infrastructure for the [Solidity
compiler](https://github.com/argotorg/solidity): AFL++ harnesses, fuzzers,
and debug runners to reproduce findings.

## Two build trees

Everything builds natively on the host — no Docker, no libc++.

- `build/` — host gcc/clang: `solc`, the `*_debug_runner` crash-repro
  tools, and the AFL toolchain (afl-clang-fast, afl-ts, grammar).
- `build_afl/` — `afl-clang-fast++`: the AFL fuzzers — protobuf harnesses
  (`*_proto_ossfuzz_*`) and the differential `.sol` fuzzer
  (`sol_afl_diff_runner`).

They never share object files; rebuild one without touching the other.

## Setup

```bash
git clone --recurse-submodules \
  https://github.com/argotorg/solidity-fuzzing.git
cd solidity-fuzzing      # or: git submodule update --init --recursive
```

Needs: gcc/g++ (C++20), clang/clang++, llvm-dev, cmake (>=3.13), make,
ninja, boost (incl. static libs), protobuf + abseil, protoc, ccache, gdb.

Apply the local solidity patches (idempotent):

```bash
for p in patches/*.patch; do
  echo "Applying patch $p"
  git apply --reverse --check "$p" 2>/dev/null || git apply "$p"
done
```

## Build

```bash
# 1. solc + debug runners (build/)
mkdir -p build && cd build && cmake .. && make -j$(nproc) && cd ..

# 2. AFL toolchain — afl-clang-fast, afl-ts, grammar (needs llvm-dev)
make -C build -j$(nproc) aflplusplus afl_ts tree_sitter_solidity

# 3. AFL fuzzers (build_afl/)
tools/ossfuzz/build_ossfuzz.sh            # protobuf fuzzers + LPM mutators
tools/afl/build_instrumented.sh     # differential .sol fuzzer
```

`tools/ossfuzz/build_ossfuzz.sh` builds libprotobuf-mutator into `deps_afl/`
(against the system protobuf), one LPM custom mutator per grammar, and the
fuzzers into `build_afl/`. See [tools/ossfuzz](tools/ossfuzz/README.md).

## Run

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern   # one-time, AFL needs it

# Protobuf fuzzers — afl-fuzz + the matching LPM grammar mutator:
tools/ossfuzz/run_ossfuzz_afl.sh sol_proto_ossfuzz_evmone corpus_sol
tools/ossfuzz/run_ossfuzz_afl.sh yul_proto_ossfuzz_evmone corpus_yul
tools/ossfuzz/run_ossfuzz_afl.sh sol_ice_ossfuzz seeds_sol_ice

# Differential .sol fuzzer (afl-ts AST mutator):
tools/afl/run_afl.sh                 # or run_afl_parallel.sh -j 8
```

## Generative fuzzer ("ossfuzz") triage

```bash
./yul_crash_categorizer.py results/639-yul_proto_ossfuzz_evmone_ssacfg/findings/*/crashes/
./sol_crash_categorizer.py results/637-sol_proto_ossfuzz_evmone_viair/findings/*/crashes/
./sol_ice_crash_backtrace_categorizer.py results/643-sol_ice_ossfuzz/findings/*/crashes
```

Without categorization:
```bash
run_ice_crashes.py
./run_sol_crashes.py --fuzzer build_afl/tools/ossfuzz/sol_proto_ossfuzz_evmone_viair ./results/637-sol_proto_ossfuzz_evmone_viair/findings/*/crashes/
./run_yul_crashes.py ./results/637-sol_proto_ossfuzz_evmone_viair/findings/*/crashes/
```


## Non-generative fuzzer ("afl") triage

```bash
./run_afl_crashes.py ./results/645-afl/findings/*/crashes # gives nice table, with backtrace
run_afl_hangs.py
rerender_afl_hangs.py
```


### AFL diff-runner regression tests

```bash
make -C build -j$(nproc) sol_afl_diff_runner
tools/afl/tests/run.sh               # every inputs/*.sol must exit 0
```
