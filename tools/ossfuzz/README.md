## Executables generated

This directory contain test harnesses in  C/C++ that define the `LLVMFuzzerTestOneInput` API.
All differential fuzzers use the latest EVM version.

### Differential fuzzers (LibFuzzer + EVMOne + ProtoBuf)

These check whether a system generates the same LOGs, STATE, and RETURNDATA when deployed
and ran with a fuzz-generated CALLDATA. Hence, these are differential fuzzers over the
deployed (via EVMOne) bytcode.

| Executable | Source / Mode | What it compares |
|---|---|---|
| `sol_proto_ossfuzz_evmone` | `solProtoFuzzer2.cpp` | Unopt vs opt (same `viaIR` flag, chosen by input) |
| `sol_proto_ossfuzz_evmone_viair` | `solProtoFuzzer2.cpp` | Legacy unopt (viaIR=false) vs IR opt (viaIR=true) |
| `yul_proto_ossfuzz_evmone` | `yulProtoFuzzerEvmone.cpp` | Unopt Yul vs fully-optimized Yul |
| `yul_proto_ossfuzz_evmone_ssacfg` | `yulProtoFuzzerEvmone.cpp` | Unopt legacy codegen vs opt SSA CFG codegen |
| `yul_proto_ossfuzz_evmone_single_pass_<abbr>` | `yulProtoFuzzerEvmone.cpp` | Prereq passes only vs prereq + one pass: `c S L M s r D` |
| `yul_proto_ossfuzz_evmone_no_ssa` | `yulProtoFuzzerEvmone.cpp`  | Unopt vs full opt  w/ SSATransform stripped |
| `yul_proto_ossfuzz_evmone_check_stack_alloc` | `yulProtoFuzzerEvmone.cpp`, | Opt with stack alloc off vs on (legacy codegen) |

Pass abbreviations currently built: `c` CommonSubexpressionEliminator, `S`
UnusedStoreEliminator, `L` LoadResolver, `M` LoopInvariantCodeMotion, `s`
ExpressionSimplifier, `r` UnusedAssignEliminator, `D` DeadCodeEliminator.


### Non-differential fuzzers (LibFuzzer + EVMOne)

| Executable | Source / Mode | What it checks |
|---|---|---|
| `sol_proto_ossfuzz_nondiff` | `solProtoFuzzer.cpp` | Self-checking `test()` must not revert and must return 0 |
| `sol_recstruct_alias_ossfuzz` | `solRecStructAliasFuzzer.cpp` | Aliased storage struct copy (#1392) |
| `sol_roundtrip_ossfuzz` | `solRoundtripFuzzer.cpp` | Primitive-type identity oracles |


### Crash-only fuzzers (LibFuzzer, no EVMOne)

| Executable | Source | What it feeds random bytes to |
|---|---|---|
| `sol_ice_ossfuzz` | `sol_ice_ossfuzz.cpp` | Solidity frontend `sol2Proto` → `CompilerStack::compile` |
| `shuffler_proto_ossfuzz` | `shufflerProtoFuzzer.cpp` | SSA stack shuffler |


### Legacy fuzzers

| Executable | Source | What it feeds random bytes to |
|---|---|---|
| `strictasm_opt_ossfuzz` | `strictasm_opt_ossfuzz.cpp` | Yul optimizer |
| `strictasm_assembly_ossfuzz` | `strictasm_assembly_ossfuzz.cpp` | Yul assembler |
| `const_opt_ossfuzz` | `const_opt_ossfuzz.cpp` | Constant optimizer |
| `solc_ossfuzz` | `solc_ossfuzz.cpp` | Solidity compiler |
| `solc_mutator_ossfuzz` | `solc_ossfuzz.cpp` + custom mutator | Solidity compiler |


`solidity.dict` contains Solidity-specific syntactical tokens that are more
likely to guide the fuzzer towards generating parseable and varied Solidity
input.

## Debugging stack-shuffler crashes with `stackshuffler`

`shuffler_proto_ossfuzz` finds crashes in the SSA stack shuffler. Each crash
artifact is a raw protobuf — to inspect it by eye, or to feed it to the
standalone `stackshuffler` CLI, dump it to the `.stack` file format first:

```bash
# 1. Build the standalone shuffler (from a normal, non-ossfuzz build):
mkdir -p build && cd build && cmake .. && make -j$(nproc) stackshuffler && cd ..

# 2. Dump the crash input to a .stack file. The fuzzer recognises
#    PROTO_FUZZER_DUMP_PATH: when set, it writes the converted shuffler input
#    (initial, targetStackTop, targetStackTailSet, targetStackSize) to that
#    path, then proceeds with the same run that originally crashed.
PROTO_FUZZER_DUMP_PATH=bad.stack \
  ./build_ossfuzz/tools/ossfuzz/shuffler_proto_ossfuzz crash-<hash>

# 3. Reproduce outside the fuzzer with the standalone CLI. --verbose prints
#    the full trace table (initial stack, every emitted op, final row).
./build/tools/shuffler-fuzzer/stackshuffler --verbose bad.stack
```

Example `bad.stack`:

```
initial: [v0, JUNK]
targetStackTop: []
targetStackTailSet: {lit10}
targetStackSize: 1
```

Exit code `1` + `Status: MaxIterationsReached` means the shuffler gave up; exit
code `0` + `Status: Admissible` means it converged. Note that only a subset of
shuffler bugs surface in the standalone tool — the fuzzer also checks an
independent replay oracle (see `shufflerProtoFuzzer.cpp`) that the standalone
CLI does not run.

### Stack-too-deep suppression

The fuzzer currently silences exceptions whose message contains "stack too
deep" (case-insensitive) — those cases are honest shuffler give-ups, not bugs,
until the shuffler learns to handle them. To flip this off and treat every
shuffler-thrown assertion as a crash, add
`-DFUZZER_MODE_STACK_TOO_DEEP_IS_BUG` to `shuffler_proto_ossfuzz` in
`tools/ossfuzz/CMakeLists.txt` (mirroring the pattern used by
`yul_proto_ossfuzz_evmone_ssacfg` etc.) and rebuild.

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

   If the sequences are not given, the default sequences are used

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
rm -rf tmp
mkdir -p tmp
find corpuses/my_corpus_yul_proto_ossfuzz_evmone/ -maxdepth 1 -type f -print0 \
  | shuf -z -n 1000 \
  | while IFS= read -r -d '' file; do
      PROTO_FUZZER_DUMP_PATH="tmp/$(basename "$file").yul" \
        ./build_ossfuzz/tools/ossfuzz/yul_proto_ossfuzz_evmone "$file"
    done
```

or

```bash
rm -rf tmp
mkdir -p tmp
find corpuses/my_corpus_sol_proto_ossfuzz_evmone/ -maxdepth 1 -type f -print0 \
  | shuf -z -n 1000 \
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

## OSSFuzz notes

[oss-fuzz][1] is Google's fuzzing infrastructure that performs continuous
fuzzing. What this means is that, each and every upstream commit is
automatically fetched by the infrastructure and fuzzed on a daily basis.

We have configuration files:here with the `.options` extension that are
parsed by oss-fuzz. The only option that we use currently is the `dictionary`
option that asks the fuzzing engines behind oss-fuzz to use the specified
dictionary. The specified dictionary happens to be `solidity.dict`.

[1]: https://github.com/google/oss-fuzz
[2]: https://github.com/google/oss-fuzz/issues/1114#issuecomment-360660201

