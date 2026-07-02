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

Apply the local solidity patches (EVMHost fixes; idempotent):

```bash
for p in patches/*.patch; do
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

# Differential .sol fuzzer (afl-ts AST mutator):
tools/afl/run_afl.sh                 # or run_afl_parallel.sh -j 8
```

See [tools/ossfuzz](tools/ossfuzz/README.md) and
[tools/afl](tools/afl/README.md) for the fuzzer lists and triage.

## Reproduce a finding

```bash
# Dump source from a crash, then replay (debug runners live in build/):
PROTO_FUZZER_DUMP_PATH=bad.sol \
  build_afl/tools/ossfuzz/sol_proto_ossfuzz_evmone crash-file
build/tools/runners/sol_debug_runner bad.sol        # 0 ok, 1 diff, 2 compile-fail, 3 ICE

# Yul equivalent:
PROTO_FUZZER_DUMP_PATH=bad.yul \
  build_afl/tools/ossfuzz/yul_proto_ossfuzz_evmone crash-file
build/tools/runners/yul_debug_runner bad.yul

# AFL .sol crash (the file embeds calldata) — needs --afl:
build/tools/runners/sol_debug_runner --afl findings_*/default/crashes/id:...
```

### AFL diff-runner regression tests

```bash
make -C build -j$(nproc) sol_afl_diff_runner
tools/afl/tests/run.sh               # every inputs/*.sol must exit 0
```
