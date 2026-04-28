# Solidity Fuzzing Tools

Fuzzing infrastructure for the [Solidity
compiler](https://github.com/argotorg/solidity). Contains OSS-Fuzz harnesses,
fuzzers, and debug runners to debug & reproduce findings.

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

## Running Debug Systems

```bash
# Reproduce a sol ProtoBuf EVMOne finding:
./build/sol_debug_runner crash.sol

# Reproduce a Yul Protobuf EVMOne finding:
./build/yul_debug_runner crash.yul
```

### Replaying a Yul single-pass crash corpus

`run_s_crash.py` walks a corpus of `crash-<hash>` protobuf inputs produced by
one of the `yul_proto_ossfuzz_evmone_single_pass_<pass>` fuzzers, dumps each
to Yul (`crash-<hash>.yul`) and replays it through `yul_debug_runner` with the
matching single-step optimizer sequence, capturing the full verbose output to
`crash-<hash>.out` next to the input.

```bash
# Process s_crash/ (the default for pass 's'):
./run_s_crash.py -p s

# Other passes (binary must exist under build_ossfuzz/tools/ossfuzz/):
./run_s_crash.py -p c
./run_s_crash.py -p L --crash-dir my_corpus
```

Valid pass abbreviations: `c S L M s r D` (see CLAUDE.md for the matching
binaries). Both build trees must be present.

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

