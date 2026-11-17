# Solidity Fuzzing Tools

Fuzzing infrastructure for the [Solidity
compiler](https://github.com/argotorg/solidity): AFL++ harnesses, fuzzers,
and debug runners to reproduce findings.

## Quick start (nix)

On a machine with [nix](https://nixos.org) (flakes enabled), `flake.nix` provides the whole toolchain and
`tools/bootstrap.py` builds everything — AFL++, both build trees, all fuzzers and the seed corpus:

```bash
git clone --recurse-submodules https://github.com/argotorg/solidity-fuzzing.git
cd solidity-fuzzing
nix develop --command python3 tools/bootstrap.py
```

- Steps: `--steps afl,host,proto,aflharness,corpus` (default: all, in that order); each logs to
  `bootstrap_logs/<step>.log`.
- Jobs: `-j N`; the default is min(physical cores, available RAM / 1.5 GB), since each solidity compile
  takes ~1-1.5 GB.
- Use `nix develop`, not `nix shell`: the build needs the dev shell's compiler/library setup. Without
  flakes enabled, add `--extra-experimental-features 'nix-command flakes'`.
- The first `nix develop` builds a static Boost from source (not in the binary cache), so it takes a few
  minutes.
- A checkout copied from another machine is fine: `build/`, `build_afl/` and `deps_afl/` configured for a
  different path are deleted and rebuilt, and AFL++, afl-ts and the grammar library are always rebuilt from
  clean.
- Before fuzzing: `echo core | sudo tee /proc/sys/kernel/core_pattern`.

Without nix, install the packages listed under [Setup](#setup) and follow [Build](#build).

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

Needs: gcc/g++ (C++23), clang/clang++, llvm-dev, lld, cmake (>=3.20), make,
ninja, boost (incl. static libs), protobuf + abseil, protoc, ccache, gdb,
python3, cargo (corpus generator). `flake.nix` lists exactly these.

## Build

```bash
# 1. solc + debug runners (build/)
mkdir -p build && cd build && cmake .. && make -j$(nproc) && cd ..

# 2. AFL toolchain — afl-clang-fast, afl-ts, grammar (needs llvm-dev)
make -C build -j$(nproc) aflplusplus afl_ts tree_sitter_solidity

# 3. AFL fuzzers (build_afl/)
tools/ossfuzz/build_ossfuzz.sh            # protobuf fuzzers + LPM mutators
tools/afl/build_instrumented.sh     # differential .sol fuzzer, all oracle modes
```

The build scripts use `-j$(nproc)`; set `BUILD_JOBS=N` on machines with less than ~1.5 GB RAM per core.

`tools/ossfuzz/build_ossfuzz.sh` builds libprotobuf-mutator into `deps_afl/`
(against the system protobuf), one LPM custom mutator per grammar, and the
fuzzers into `build_afl/`. See [tools/ossfuzz](tools/ossfuzz/README.md).

## Run

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern   # one-time, AFL needs it

# Protobuf fuzzers — afl-fuzz + the matching LPM grammar mutator:
tools/ossfuzz/run_ossfuzz_afl.sh yul_proto_ossfuzz_evmone corpus_yul

# Differential .sol fuzzer (afl-ts AST mutator); MODE picks the oracle, default
# sol_afl_diff_runner_viair (legacy vs via-IR), see tools/afl/README.md:
tools/afl/run_afl.sh                 # or run_afl_parallel.sh -j 8

# Fixed-duration campaign over several fuzzers at once, then a stats table:
tools/afl/run_campaign.py --duration 3600 -o results/run1 \
    sol_afl_diff_runner_viair=16 sol_afl_ice_runner=6 yul_proto_ossfuzz_evmone=8
```

## Generative fuzzer ("ossfuzz") triage

```bash
./yul_crash_categorizer.py results/639-yul_proto_ossfuzz_evmone_ssacfg/findings/*/crashes/
```

Without categorization:
```bash
./run_yul_crashes.py ./results/639-yul_proto_ossfuzz_evmone_ssacfg/findings/*/crashes/
```


## Non-generative fuzzer ("afl") triage

```bash
./run_afl_crashes.py ./results/645-afl/findings/*/crashes # gives nice table, with backtrace
./run_afl_crashes.py results/run1/sol_afl_diff_runner_viair --mode sol_afl_diff_runner_viair  # buckets.txt: one line per root cause
run_afl_hangs.py
rerender_afl_hangs.py
```


### AFL diff-runner regression tests

```bash
make -C build -j$(nproc) sol_afl_diff_runner
tools/afl/tests/run.sh               # every inputs/*.sol must exit 0
```
