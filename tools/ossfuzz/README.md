## Intro

[oss-fuzz][1] is Google's fuzzing infrastructure that performs continuous
fuzzing. What this means is that, each and every upstream commit is
automatically fetched by the infrastructure and fuzzed on a daily basis.

## What does the ossfuzz directory contain?

To help oss-fuzz do this, we (as project maintainers) need to provide the
following:

- test harnesses: C/C++ tests that define the `LLVMFuzzerTestOneInput` API.
  This determines what is to be fuzz tested.
- build infrastructure: (c)make targets per fuzzing binary. Fuzzing requires
  coverage and memory instrumentation of the code to be fuzzed.
- configuration files: These are files with the `.options` extension that are
  parsed by oss-fuzz. The only option that we use currently is the `dictionary`
  option that asks the fuzzing engines behind oss-fuzz to use the specified
  dictionary. The specified dictionary happens to be `solidity.dict`.

`solidity.dict` contains Solidity-specific syntactical tokens that are more
likely to guide the fuzzer towards generating parseable and varied Solidity
input.

To be consistent and aid better evaluation of the utility of the fuzzing
dictionary, we stick to the following rules-of-thumb:
  - Full tokens such as `block.number` are preceded and followed by a
    whitespace
  - Incomplete tokens including function calls such as `msg.sender.send()`
    are abbreviated `.send(` to provide some leeway to the fuzzer to
    synthesize variants such as `address(this).send()`
  - Language keywords are suffixed by a whitespace with the exception of
    those that end a line of code such as `break;` and `continue;`

[1]: https://github.com/google/oss-fuzz
[2]: https://github.com/google/oss-fuzz/issues/1114#issuecomment-360660201

## Executables generated

Firstly, whenever relevant we ONLY use latest EVM version.

### Using LibFuzzer and differential-checking with EVMOne
- `sol_proto_ossfuzz_evmone` (from `solProtoFuzzer2.cpp`). Generates random
  Solidity via Protobuf schema `sol2Proto.proto` using `protoToSol2`, compiles
  with 2 configurations — unoptimized vs optimized — both using the same
  `viaIR` flag (chosen by the protobuf input). Deploys on evmone and compares
  output, logs, and storage.
- `sol_proto_ossfuzz_evmone_viair` (from `solProtoFuzzer2.cpp`, compiled with
  `FUZZER_MODE_VIAIR`). Generates random Solidity via Protobuf schema
  `sol2Proto.proto` using `protoToSol2`, compiles unoptimized with legacy
  codegen (viaIR=false) vs optimized with IR codegen (viaIR=true). Compares
  output, logs, and storage.
- `yul_proto_ossfuzz_evmone` (from `yulProtoFuzzerEvmone.cpp`). Generates
  random Yul via Protobuf, compiles twice (unoptimized and with the full Yul
  optimizer), deploys both versions on evmone with protobuf-generated
  calldata, and compares output data, logs, and storage.
- `yul_proto_ossfuzz_evmone_ssacfg` (from `yulProtoFuzzerEvmone.cpp`,
  compiled with `FUZZER_MODE_SSACFG`). Compares unoptimized legacy codegen
  vs optimized SSA CFG codegen — tests the newer SSA-based code generation
  backend against the legacy stack-based one.
- `yul_proto_ossfuzz_evmone_single_pass` (from `yulProtoFuzzerEvmone.cpp`,
  compiled with `FUZZER_MODE_SINGLE_PASS`). Tests individual Yul optimizer
  passes in isolation. Run A applies only the hard-coded prerequisite passes
  (Disambiguator + `hgfo`) with an empty optimizer sequence; Run B applies the
  same prerequisites plus a single target optimizer pass. Both use legacy
  codegen with `optimizeStackAllocation` off, so the only semantic difference
  is the one target pass. The target pass is selected at runtime via the
  `FUZZER_PASS` environment variable — a single character abbreviation (e.g.
  `c` for CommonSubexpressionEliminator, `S` for UnusedStoreEliminator). Run
  without `FUZZER_PASS` set to see all valid abbreviations. Usage:
  ```bash
  # Run multiple passes in parallel (one process per pass):
  DIR=`pwd`
  for pass in c S L M s r D; do
    mkdir -p my_corpus_$pass
    tmux new-window -t "0" -c "$DIR" -n "fuzz-$i"
    tmux send-keys -t "$SESSION:$i" "$CMD" Enter
    FUZZER_PASS=$pass ./build_ossfuzz/tools/ossfuzz/yul_proto_ossfuzz_evmone_single_pass \
      my_corpus_$pass/ &
  done
  ```

### Using LibFuzzer and executing with EVMOne, checking the known output
- `yul_proto_ossfuzz_evmone_check_stack_alloc` (from
  `yulProtoFuzzerEvmone.cpp`, compiled with `FUZZER_MODE_CHECK_STACK_ALLOC`).
  Compares optimized Yul with `optimizeStackAllocation` off vs on (both legacy
  codegen). Catches miscompilations introduced by the stack-reuse
  code-generation pass.
- `sol_proto_ossfuzz_nondiff` (from `solProtoFuzzer.cpp`). Generates random
  Solidity via the Protobuf schema `solProto.proto`, producing code with
  functions that return known constants. Compiles with minimal optimizer
  settings, deploys on evmone, asserts `test()` does not revert and returns
  0 (i.e. all constants are returned correctly). Not differential — single
  configuration only.

### Using LibFuzzer, Checking for Internal Crash
- `strictasm_opt_ossfuzz` (from `strictasm_opt_ossfuzz.cpp`). Interprets
  random characters as strict assembly code, runs the optimizer, and hopes
  it crashes.
- `strictasm_assembly_ossfuzz` (from `strictasm_assembly_ossfuzz.cpp`).
  Interprets random characters as strict assembly code, assembles it, and
  hopes it crashes.
- `const_opt_ossfuzz` (from `const_opt_ossfuzz.cpp`). Interprets random
  characters as some kind of constants, runs the constant optimizer, and
  hopes it crashes.
- `solc_ossfuzz` (from `solc_ossfuzz.cpp`). Interprets random characters as
  Solidity code, compiles and hopes it crashes.
- `solc_mutator_ossfuzz` (from `solc_ossfuzz.cpp`). Same as previous, but with
  a custom mutator included.

## Debugging solidity issues with `sol_debug_runner`

`sol_debug_runner` is a standalone tool for debugging differential testing
failures and internal compiler crashes from `sol_proto_ossfuzz_evmone`. It
takes a `.sol` file and runs it through the same compile-deploy-execute
pipeline as the fuzzer, across all 4 configurations:
`{noOpt, opt} x {viaIR=true, viaIR=false}`. It prints bytecodes, EVM
execution results, logs, and storage for each, then reports which
differential comparisons pass or fail.

### Reproducing a fuzzer crash

1. Dump the Yul/Solidity source from a crash input:

  ```bash
  PROTO_FUZZER_DUMP_PATH=tout.yul PROTO_FUZZER_DUMP_SEQ_PATH=tout.seq \
    ./build_ossfuzz/tools/ossfuzz/yul_proto_ossfuzz_evmone crash-bd3e51cef7024834e7a83e27e361a611c7dce954
   ```

2. Run the debug tool:

   ```bash
   mkdir -p /tmp/debug-output
    ./build/yul_debug_runner tout.yul --verbose \
    --optimizer-sequence "<seq from tout.seq>" \
    --optimizer-cleanup-sequence "<cleanup from tout.seq>"
   ```

3. Check the terminal output. The tool prints per-configuration details
   (bytecode, status, logs, storage) followed by a differential comparison
   section:

   ```
   ========== DIFFERENTIAL COMPARISONS ==========

   --- Comparing noOpt_viaIR=true vs opt_viaIR=true ---
     Status:  MATCH (SUCCESS vs SUCCESS)
     Output:  MATCH
     Logs:    DIFFER
     Storage: MATCH
   ```

4. Inspect files in `--output-dir`:
   - `<config>.bytecode.hex` — compiled bytecode in hex
   - `<config>.log` — full execution details (status, output, logs, storage)

### CLI options

```
./build/sol_debug_runner <file.sol> [--output-dir <dir>] [--via-ir true|false] [--calldata <hex>] [--quiet]
```

- `<file.sol>` — Solidity source file (positional, required)
- `--output-dir <dir>` — write bytecode and log files here (optional)
- `--via-ir true|false` — initial viaIR setting (default: `true`). The tool
  always tests both values; this controls which is "primary".
- `--calldata <hex>` — extra calldata in hex (e.g. `a0ffba`), appended after
  the `test()` method selector
- `--quiet` — suppress all output except a one-line summary (`OK`,
  `MISMATCH`, or `INTERNAL_ERROR`). Used by the delta debugger.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All match — no bug |
| 1 | Differential mismatch found |
| 2 | Normal compilation failure / file error |
| 3 | Internal compiler error (assertion failure, crash) |


## Debugging Yul issues with `yul_debug_runner`

`yul_debug_runner` is the Yul equivalent of `sol_debug_runner`. It reproduces
the `yul_proto_ossfuzz_evmone`, `yul_proto_ossfuzz_evmone_ssacfg`, and
`yul_proto_ossfuzz_evmone_check_stack_alloc` fuzzers' compile-deploy-execute
flow on a `.yul` file. It runs four configurations (unoptimized, optimized
legacy, optimized SSACFG, optimized legacy without stack allocation), deploys
all on evmone, and compares output, logs, and storage across pairs. Always
uses the latest EVM version.

### Building

Build using the normal (non-ossfuzz) cmake build (see the main README for the
full cmake invocation):

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc) yul_debug_runner
```

### Reproducing a fuzzer crash

1. Dump the Yul source from a crash input:

   ```bash
   PROTO_FUZZER_DUMP_PATH=bad.yul \
     ./build_ossfuzz/tools/ossfuzz/yul_proto_ossfuzz_evmone crash-<hash>
   ```

2. Run the debug tool:

   ```bash
     ./build/yul_debug_runner bad.yul
   ```

3. Check the terminal output. The tool prints per-configuration details
   (bytecode, status, logs, storage) followed by a differential comparison
   section:

   ```
   ========== DIFFERENTIAL COMPARISONS ==========

   --- Comparing unoptimized vs optimized_legacy ---
     Status:  MATCH (SUCCESS vs SUCCESS)
     Output:  MATCH
     Logs:    DIFFER
     Storage: MATCH

   --- Comparing unoptimized vs optimized_ssacfg ---
     Status:  MATCH (SUCCESS vs SUCCESS)
     Output:  MATCH
     Logs:    MATCH
     Storage: MATCH

   --- Comparing optimized_legacy vs optimized_ssacfg ---
     Status:  MATCH (SUCCESS vs SUCCESS)
     Output:  MATCH
     Logs:    DIFFER
     Storage: MATCH

   --- Comparing optimized_legacy_no_stack_alloc vs optimized_legacy ---
     Status:  MATCH (SUCCESS vs SUCCESS)
     Output:  MATCH
     Logs:    MATCH
     Storage: MATCH
   ```

4. Optionally write output files:

   ```bash
     ./build/yul_debug_runner bad.yul --output-dir /tmp/debug-output
   ```

### CLI options

```
./build/yul_debug_runner <file.yul> [--output-dir <dir>] [--calldata <hex>] [--quiet]
```

- `<file.yul>` — Yul source file (positional, required)
- `--output-dir <dir>` — write bytecode and log files here (optional)
- `--calldata <hex>` — calldata in hex (e.g. `a0ffba`), passed to the
  deployed contract
- `--quiet` — suppress all output except a one-line summary (`OK`,
  `MISMATCH`, or `INTERNAL_ERROR`). Used by delta debuggers.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All match — no bug |
| 1 | Differential mismatch found |
| 2 | Normal compilation failure / file error |
| 3 | Internal compiler error (assertion failure, crash) |


## Checking generated Solidity with check_sol_proto_files.py

`check_sol_proto_files.py` compiles a directory of generated `.sol` files
with `solc` and reports errors, warnings, and a tally of which language
features appear. It is useful for verifying that the protobuf-to-Solidity
converter (`protoToSol2`) produces valid code and for assessing corpus
coverage.

### Dumping `.sol` files from a corpus

First, dump Solidity source from fuzzer corpus entries:

```bash
mkdir -p tmp
rm tmp/*.sol
find my_corpus_sol_proto_ossfuzz_evmone/ -maxdepth 1 -type f -print0 \
  | shuf -z -n 200 \
  | while IFS= read -r -d '' file; do
      PROTO_FUZZER_DUMP_PATH="tmp/$(basename "$file").sol" \
        ./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone "$file"
    done
```

### Running the checker

```bash
python3 tools/ossfuzz/check_sol_proto_files.py tmp/ \
  --solc ./build/solc/solc
```

### CLI options

- `<sol_dir>` — directory containing `.sol` files (positional, required)
- `--solc <path>` — path to `solc` binary (default: `solc`)
- `--no-compile` — skip compilation, only tally features
- `--max-files <N>` — process at most N files (default: all)

### Output

The tool prints two sections:

**Compilation results** — total errors, warnings, and breakdowns by type.
Files with errors are listed with their first few error messages. Example:

```
============================================================
COMPILATION RESULTS
============================================================
Files compiled:  50
Files with errors: 0
Total errors:    0
Total warnings:  104

Warning types:
  This is a pre-release compiler version, ...: 50
  Unused function parameter. ...: 22
```

**Feature tally** — counts of language features grouped by category (contract
structure, functions, state variables, types, events/errors, control flow,
expressions, builtins, and new features). For each feature it shows the total
occurrence count and how many files contain it. Example:

```
  New Features (this PR):
    ether_units                     (none)
    indexed_params                  total=     1  files=    1/50
    array_push                      (none)
    returns_two                     total=     2  files=    2/50
    free_functions                  total=    50  files=   34/50
```

Features showing `(none)` indicate the fuzzer corpus hasn't grown large
enough to produce those protobuf field combinations yet — this is normal for
a young corpus.

## Quick corpus check with check_diversity_and_errors.sh

`check_diversity_and_errors.sh` is a convenience wrapper that dumps `.sol`
files from a fuzzer corpus and pipes them through `check_sol_proto_files.py`
in one step. It picks N random corpus entries, runs the fuzzer binary to dump
their Solidity source, compiles them with `solc`, and reports errors + feature
diversity.

### Usage

```bash
# Default fuzzer (sol_proto_ossfuzz_evmone), 300 files:
./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone 300

# Explicit fuzzer binary:
./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone 300 \
  ./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone

# viaIR variant:
./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone_viair 300 \
  ./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone_viair
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<corpus_dir>` | Directory containing fuzzer corpus files (required) |
| `<num_files>` | Number of random corpus entries to sample (required) |
| `[fuzzer_binary]` | Path to fuzzer binary (default: `./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone`) |

The script expects `./build/solc/solc` for compilation checks and
`./tools/ossfuzz/check_sol_proto_files.py` for the analysis. Dumped
files go into a temporary directory that is cleaned up automatically.
