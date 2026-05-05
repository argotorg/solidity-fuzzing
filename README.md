# Solidity Fuzzing Tools

Fuzzing infrastructure for the [Solidity
compiler](https://github.com/argotorg/solidity). Contains OSS-Fuzz harnesses,
fuzzers, and debug runners to debug & reproduce findings.

## Three workflows, three build trees

The repo supports three independent fuzzing workflows. Each uses its own
toolchain and its own out-of-tree build directory; they never share object
files, so you can rebuild any one without touching the others.

| Tree             | Compiler                  | Workflow / artefacts                                                                |
| ---              | ---                       | ---                                                                                 |
| `build/`         | host gcc/clang            | `solc`, debug runners (`sol_debug_runner`, `yul_debug_runner`), host AFL harness — for reproducing crashes |
| `build_ossfuzz/` | clang + libc++ (in Docker) | OSS-Fuzz libFuzzer harnesses (`sol_proto_ossfuzz_*`, `yul_proto_ossfuzz_*`, …)      |
| `build_afl/`     | `afl-clang-fast`          | AFL++ differential fuzzer (`sol_afl_diff_runner`) with edge-coverage instrumentation |

The fuzz build **must** go through Docker — libFuzzer + MemorySanitizer
require an instrumented libc++ that only the OSS-Fuzz Docker image
ships. Sections below cover each tree in turn.

## Cloning and Setup

```bash
git clone --recurse-submodules https://github.com/argotorg/solidity-fuzzing.git
cd solidity-fuzzing

# Or if already cloned without submodules:
git submodule update --init --recursive
```

Make sure to have the following installed:
* gcc / g++ (C++20 support required, i.e. GCC 10+)
* cmake (>= 3.13)
* make
* libboost-dev, libboost-program-options-dev, libboost-filesystem-dev
* linux-perf
* gdb
* protobuf-compiler (protoc)
* ccache
* docker

## Building Solidity and the Debug Tools, i.e. "normal build"

We'll need a full solidity build along with debug tools (`sol_debug_runner`,
`yul_debug_runner`) built with a standard CMake workflow. They link against the
solidity libraries built from the submodule.

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer" -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" ..
make -j$(nproc)
cd ..
```

This builds the following debug tools:
- `sol_debug_runner` — reproduces `sol_proto_ossfuzz_evmone*` findings
  (and, with `--afl`, AFL crashes from `sol_afl_diff_runner`)
- `yul_debug_runner` — reproduces `yul_proto_ossfuzz_evmone*` findings

## Building OSS-Fuzz Docker Image

```bash
docker build -t solidity-ossfuzz -f scripts/docker/Dockerfile.ubuntu.clang.ossfuzz .
```

## Building Fuzzers using the Docker Image, i.e. "fuzz build"

```bash
docker run --rm -v "$(pwd)":/src/solidity-fuzzing -ti solidity-ossfuzz \
    /src/solidity-fuzzing/scripts/build_ossfuzz.sh
```

This builds all relevant fuzzer targets under `build_ossfuzz`.
The most important are the libfuzzer-based protobuf targets to be ran standalone:
- `sol_proto_ossfuzz_*` — Solidity differential fuzzers
- `yul_proto_ossfuzz_*` — Yul differential fuzzers

## Running a libfuzzer-based Fuzzer

```bash
./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone corpus_dir
```

Corpuses are currently stored here: https://github.com/msooseth/solidity-fuzzing-corpus

## Running the AFL++ differential fuzzer

`sol_afl_diff_runner` reads a single `.sol` file, compiles + deploys it under
two optimiser settings (`minimal` vs `standard`), calls each with deterministic
calldata, and `solAssert`s that status / output / logs / storage match. On any
mismatch the unhandled exception triggers SIGABRT and AFL++ records a crash.
It works under `afl-fuzz` and standalone (file path or stdin).

Two binaries get built — same source, different toolchain:

| Path                                              | Toolchain        | When to use                                |
| ---                                               | ---              | ---                                        |
| `build/tools/afl/sol_afl_diff_runner`             | host gcc         | one-off check on a single `.sol`; reproducing crashes |
| `build_afl/tools/afl/sol_afl_diff_runner`         | `afl-clang-fast` | real fuzzing campaigns under `afl-fuzz`    |

AFL++ itself, the `afl-ts` AST-aware custom mutator, and the
`tree-sitter-solidity` grammar are all vendored as submodules — no system
AFL++ install needed. The grammar builds in the default `make` target;
AFL++ + afl-ts are opt-in (they need `clang` + `llvm-dev` that the
regular host build doesn't).

```bash
mkdir -p build && cd build && cmake .. && make -j$(nproc) && cd .. # Build solc + host harness + grammar.
make -C build -j$(nproc) aflplusplus afl_ts                        # Build the AFL toolchain (needs clang + llvm-dev + libtree-sitter-dev v0.25+).

# Build the AFL-instrumented harness in build_afl/.
tools/afl/build_instrumented.sh

# (Optional) pull ~15 real-world projects + build the merged seed corpus + expand corpus
tools/afl/fetch_realworld.sh              # pull real-world projects
tools/afl/build_corpus.sh                 # writes corpus_afl/ (~8700 files)
tools/afl/build_corpus_tsgen.sh           # grammar-driven extra surface via tsgen

# One-time system setup: AFL++ requires this kernel setting.
echo core | sudo tee /proc/sys/kernel/core_pattern

# Launch — coverage-guided AFL++ + afl-ts AST mutation, all from submodules:
tools/afl/run_afl_parallel.sh -j 8        # multi-threaded
tools/afl/run_afl.sh                      # single-threaded

# Sanity-check / quick ground-truth that a crash still reproduces with the
# exact harness AFL ran (silent on success, SIGABRT on diff):
build/tools/afl/sol_afl_diff_runner some.sol; echo $?  # 0 = no diff, 134 = mismatch

# Replay an AFL crash with full per-config diagnostics, must use --afl
build/tools/runners/sol_debug_runner --afl findings_afl/default/crashes/id:000000,...
```

See [tools/afl/README.md](tools/afl/README.md) for details on the harness,
corpus, mutator integration, and follow-up TODOs.

## Running Debug Systems

```bash
# Reproduce a sol ProtoBuf EVMOne finding:
./build/sol_debug_runner crash.sol

# Reproduce a Yul Protobuf EVMOne finding:
./build/yul_debug_runner crash.yul
```

### Replaying a Yul single-pass crash corpus

`run_yul_crashes.py -p <pass>` dumps each `crash-<hash>` in `<pass>_crash/` to
`.yul` and replays through `yul_debug_runner` with the matching single-step
optimizer, writing output to `.out`. Valid passes: `c S L M s r D`.

### Replaying an ICE crash corpus

`run_ice_crashes.py` dumps each `crash-<hash>` in `ice_crash/` to `.sol` via
`sol_ice_ossfuzz` and recompiles with `solc` (default args: `--via-ir
--optimize`, override with `--solc-args`), writing output to `.out`.

## More documentation

Please see [here](tools/ossfuzz/README.md) for the list of all the
fuzzers and the documentation on how to use the debug tools.

## FAQ

### Why the elaborate docker image to build fuzzers?

- Fuzzing binaries **must** link against libc++ and not libstdc++
  This is [because][2] (1) MemorySanitizer (which flags uses of
  uninitialized memory) depends on libc++; and (2) because libc++ is
  instrumented (to check for memory and type errors) and libstdc++ not,
  the former may find more bugs.

- Linking against libc++ requires us to compile everything solidity depends
  on from source (and link these against libc++ as well)

- To reproduce the compiler versions used by upstream oss-fuzz bots, we need
  to reuse their docker image containing the said compiler versions

- Some fuzzers depend on libprotobuf, libprotobuf-mutator, libevmone etc.
  which may not be available locally; even if they were they might not be the
  right versions

