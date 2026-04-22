# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build model — two separate build trees

This repo produces two sets of binaries from two different build directories. **They are not interchangeable.**

| Build tree       | Toolchain             | Produces                                                                          |
| ---------------- | --------------------- | --------------------------------------------------------------------------------- |
| `build/`         | Host compiler, cmake  | `solc`, `sol_debug_runner`, `yul_debug_runner`, `stackshuffler` — for reproducing |
| `build_ossfuzz/` | clang + libc++ in Docker | libFuzzer fuzzers under `tools/ossfuzz/` — for fuzzing                         |

Fuzzing binaries **must** link against libc++ (MemorySanitizer requires it; libc++ is instrumented). That is why the fuzz build only works inside the OSS-Fuzz Docker image — it pulls in the exact compiler/toolchain OSS-Fuzz uses upstream.

### Building fuzzers (build_ossfuzz/) — Docker only

```bash
docker run --rm -v "$(pwd)":/src/solidity-fuzzing -ti solidity-ossfuzz \
    /src/solidity-fuzzing/scripts/build_ossfuzz.sh
```

**Never run `cmake`/`make` directly on the host to build anything under `build_ossfuzz/`.** It will link against the wrong libc++/toolchain and either fail or silently produce a broken fuzzer. If the docker image is missing, build it first:

```bash
docker build -t solidity-ossfuzz -f scripts/docker/Dockerfile.ubuntu.clang.ossfuzz .
```

`scripts/build_ossfuzz.sh` regenerates `*.pb.{cc,h}` from the `.proto` files before building. The proto bindings are committed (so that LSP / IDE works) but are refreshed on every fuzz build.

### Building debug runners and `solc` (build/) — host cmake

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer" -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" ..
make -j$(nproc)
```

## Architecture

- `solidity/` — git submodule; built as a subdirectory of the top-level `CMakeLists.txt` with `TESTS=OFF`. All fuzzers and runners link against the resulting `solidity`/`libsolc` libraries.
- `evmone/` — git submodule; built as an `ExternalProject`. Runners `dlopen` `libevmone.so` at runtime; its directory is baked into the runner RPATH so `LD_LIBRARY_PATH` is not needed.
- `tools/common/EVMHost.{cpp,h}` — fuzz-specific extensions of solidity's EVMHost (`m_subCallOutOfGas`, `m_contractCreationOrder`). Everything links against this copy, not the one in the solidity submodule.
- `tools/ossfuzz/` — libFuzzer harnesses and their proto grammars. See `tools/ossfuzz/README.md` for the per-binary breakdown.
- `tools/runners/` — standalone reproducers (`sol_debug_runner`, `yul_debug_runner`, `sol_crash_backtrace.py`, `check_diversity_and_errors.sh`).
- `tools/shuffler-fuzzer/` — standalone `stackshuffler` CLI.
- `tools/afl/` — AFL-specific harnesses.
- `cmake/` — overrides for `fmtlib`, `nlohmann-json`, `range-v3`, submodules. Prepended to `CMAKE_MODULE_PATH` because solidity's cmake modules use `CMAKE_SOURCE_DIR`, which points at *us* when built as a subdir.

### Fuzzer families

Most `*_ossfuzz_*` binaries share a source file and are differentiated by compile definitions (see `tools/ossfuzz/CMakeLists.txt` and the table in `tools/ossfuzz/README.md`):

- `sol_proto_ossfuzz_evmone` and `sol_proto_ossfuzz_evmone_viair` — both built from `solProtoFuzzer2.cpp`; the `_viair` variant adds `-DFUZZER_MODE_VIAIR`.
- `yul_proto_ossfuzz_evmone{,_ssacfg,_check_stack_alloc,_no_ssa}` and `yul_proto_ossfuzz_evmone_single_pass_<abbr>` (one per pass in `c S L M s r D`) — all built from `yulProtoFuzzerEvmone.cpp` with `FUZZER_MODE_*` defines. The single-pass variants additionally set `FUZZER_SINGLE_PASS_CHAR="<abbr>"` so the target pass is baked in at compile time (no env var).
- `sol_ice_ossfuzz` — frontend-ICE hunter. **Deliberately** lets `InternalCompilerError`, `solAssert`, and boost assertions escape; only `UnimplementedFeatureError` + `StackTooDeep*` are caught as known non-bugs. Other `sol_proto_*` fuzzers should ignore ICE and leave it to this one.

### Proto grammar → Solidity/Yul converters

- `protoToSol.cpp` / `protoToSol.h` + `solProto.proto` — used by the legacy `sol_proto_ossfuzz_nondiff`.
- `protoToSol2.cpp` / `protoToSol2.h` + `sol2Proto.proto` — newer grammar used by the differential `sol_proto_ossfuzz_evmone*` and by `sol_ice_ossfuzz`.
- `protoToYul.cpp` + `yulProto.proto` — Yul grammar.

### Differential flow (`solProtoFuzzer2.cpp`, `yulProtoFuzzerEvmone.cpp`)

1. Convert the protobuf input to a source string.
2. Call `runOnce()` twice with two different optimizer / viaIR settings.
3. Compare `status_code`, `output_data`, logs, storage, transient storage. Mismatches are reported via `solAssert(…)` — which throws `langutil::InternalCompilerError`, so libFuzzer records the crash.
4. **Compile-path failures that are either known non-bugs or ICE are caught inside `runOnce` and surfaced as `EVMC_INTERNAL_ERROR`, which the caller skips.** These must never be caught at the outer scope — doing so would silently swallow real differential mismatches (they share the `InternalCompilerError` type with `solAssert`).

## Reproducing fuzzer findings

Crash inputs are raw protobuf; to inspect/debug, dump them to text first using env vars the fuzzer recognises, then replay with the appropriate runner:

```bash
# Sol:
PROTO_FUZZER_DUMP_PATH=bad.sol \
  ./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone crash-<hash>
./build/sol_debug_runner bad.sol

# Yul (also supports optimizer sequence dump):
PROTO_FUZZER_DUMP_PATH=bad.yul PROTO_FUZZER_DUMP_SEQ_PATH=bad.seq \
  ./build_ossfuzz/tools/ossfuzz/yul_proto_ossfuzz_evmone crash-<hash>
./build/yul_debug_runner bad.yul \
  --optimizer-sequence "<from bad.seq>" \
  --optimizer-cleanup-sequence "<from bad.seq>"

# Stack shuffler (dumps to a special .stack format):
PROTO_FUZZER_DUMP_PATH=bad.stack \
  ./build_ossfuzz/tools/ossfuzz/shuffler_proto_ossfuzz crash-<hash>
./build/tools/shuffler-fuzzer/stackshuffler --verbose bad.stack
```

### Debug-runner exit codes

| Code | Meaning                                                    |
| ---- | ---------------------------------------------------------- |
| 0    | All match — no bug                                         |
| 1    | Differential mismatch found                                |
| 2    | Normal compilation failure / file error                    |
| 3    | Internal compiler error (assertion failure, crash)         |

Both runners accept `--quiet` (used by delta debuggers) and `--output-dir` (write per-config `.bytecode.hex` and `.log`).

## Corpus diversity check

```bash
./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone 300
# Or specify a non-default fuzzer binary:
./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone_viair 300 \
  ./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone_viair
```

Wraps `check_sol_proto_files.py` — dumps N random corpus entries via the given fuzzer binary, compiles each with `./build/solc/solc`, and tallies language-feature coverage. Requires both build trees.

## Parallel fuzzing for `single_pass`

There is one binary per target pass — `yul_proto_ossfuzz_evmone_single_pass_<abbr>` — each with the pass baked in at compile time via `FUZZER_SINGLE_PASS_CHAR`. Currently built: `c S L M s r D`. To add another, extend the `foreach(pass …)` in `tools/ossfuzz/CMakeLists.txt`. See `tools/ossfuzz/README.md` for a tmux-based parallel launcher.
