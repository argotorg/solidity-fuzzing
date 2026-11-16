# AFL differential `.sol` fuzzer

Tree-sitter-mutated Solidity (afl-ts) against a differential oracle. Each input is compiled under the two
configs of the runner's mode, and both builds run the same call plan (`AflExecution.{h,cpp}`):

1. deploy the last non-abstract contract of the last source unit, with the isoltest `constructor()`
   arguments and value if the source has them, else with generated ones;
2. run the isoltest call script (`// ----` section of solidity's semantic tests: literal ABI words);
3. call every public function with ABI-encoded arguments drawn from the input's calldata region,
   boundary-biased (ether for payable ones), and for some of them a malformed copy (dirty high bits,
   non-canonical bool, negative/huge/backward tail offsets);
4. call every function again in an input-chosen order with fresh arguments, so it sees the state the
   others wrote;
5. send the raw calldata region itself.

Per call the status, output/revert data, outgoing calls (normalized, as a multiset) and transient storage
must agree; at the end, logs and storage. `pragma solidity` version constraints are dropped before compiling.
A mismatch aborts (SIGABRT) and AFL records a crash. `sol_debug_runner --afl` replays the identical plan.

| Binary | Compares |
|---|---|
| `sol_afl_diff_runner_viair` (default for the run scripts) | legacy-opt vs ir-opt |
| `sol_afl_diff_runner` | legacy vs legacy-opt |
| `sol_afl_diff_runner_viair_opt` | ir vs ir-opt |
| `sol_afl_diff_runner_ssacfg` | ir-opt vs ssacfg-opt |
| `sol_afl_diff_runner_optseq` | ir-opt vs ir-opt with a Yul step sequence and `runs` drawn from a hash of the source |
| `sol_afl_diff_runner_evmversion` | ir-opt at the current EVM version vs at Paris (no PUSH0/MCOPY/transient storage) |
| `sol_afl_ice_runner` | compiles only, under all four legacy/IR × opt configs; ICEs crash (bucketed by throw site) |

Skipped as config-dependent by design: sources with `assembly`, `gas()`, `creationCode`/`runtimeCode`;
in the viaIR mode also `abicoder v1`, isoltest `compileViaYul:` tests and the documented legacy/IR semantic
changes (state variable initialization order, a modifier placeholder that can run twice; checked on the AST);
with the legacy optimizer, internal function pointer comparison (warning 3075);
runs that EXTCODECOPY/EXTCODEHASH a deployed contract; anything after an out-of-gas. EXTCODESIZE of a
deployed contract reports a fixed size instead (solc checks it before every external call).

For the protobuf fuzzers (`*_proto_ossfuzz_*`) see
[../ossfuzz](../ossfuzz/README.md); this dir is just the `.sol` fuzzer.

## Build

```bash
tools/afl/build_afl.sh             # build/: toolchain, mutator, grammar
tools/afl/build_instrumented.sh    # build_afl/: instrumented harness
```

The toolchain is vendored as submodules — no system AFL++ needed:
AFLplusplus (afl-fuzz, afl-clang-fast), afl-ts (`libts.so`, an AST-splice
custom mutator), tree-sitter-solidity (grammar), tsgen (corpus generator).

## Corpus & run

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern   # one-time

tools/afl/fetch_realworld.sh       # pull real-world projects
tools/afl/build_corpus.sh          # -> corpus_afl/, incl. rwb_* bundles (bundle_realworld.py: file + its imports)
tools/afl/build_corpus_tsgen.sh    # grammar-driven extra surface
cp corpus_tsgen/*.sol corpus_afl/

tools/afl/run_afl.sh               # single core (afl-ts mutator); MODE=<binary> picks the oracle
tools/afl/run_afl_parallel.sh -j 8 # tmux: 1 main + N-1 secondaries, findings_afl_<mode>/

# Fixed-duration multi-mode campaign without tmux, then a per-fuzzer stats table (proto fuzzers allowed
# too, for head-to-head comparisons):
tools/afl/run_campaign.py --duration 3600 -o results/run1 \
    sol_afl_diff_runner_viair=16 sol_afl_diff_runner_ssacfg=6 sol_afl_ice_runner=6 \
    sol_proto_ossfuzz_evmone_viair=8
```

`run_afl.sh` loads `libts.so` as the custom mutator plus the grammar; set
`AFL_TS_LIB=` to fall back to plain byte mutation.

### Input format

Plain `.sol` works (calldata = `keccak256(source)`). With afl-ts the
region-aware shape also carries calldata:

```
[ source ][ calldata ][ u16 LE source_len ][ 0xCA 0xFE ]
```

afl-ts splices only the source through tree-sitter; AFL's havoc mutates
the calldata. `build_corpus.sh` seeds some entries in this shape.

## Triage

Crashes land in `findings_afl/*/crashes/`, hangs (slower than `-t`) in
`hangs/`. `sig:06` = the diff oracle fired. Replay with full per-config
diffs (needs `--afl`, since the file embeds calldata):

```bash
build/tools/runners/sol_debug_runner --afl findings_afl/default/crashes/id:...
# 0 match, 1 mismatch, 2 compile fail, 3 ICE
AFLplusplus/afl-tmin -i <crash> -o min.sol \
  -- build_afl/tools/afl/sol_afl_diff_runner
```

A hang is just an input slower than the 2 s timeout; many don't
reproduce. Time each with `timeout 30 ... sol_afl_diff_runner <hang>`;
only consistently slow ones are real DoS candidates.

Bucket a campaign's crashes (dedups, cross-checks with `sol_debug_runner --afl`, labels known-noise
classes, groups ICEs by throw site):

```bash
python3 run_afl_crashes.py results/run1/sol_afl_diff_runner_viair --mode sol_afl_diff_runner_viair -o triage_viair
```

`AFL_RUNNER_VERBOSE=1 <runner> <input>` prints where the input stopped, the plan and every call's status per
config; `=2` adds each call's calldata.

## Sweeps

`tools/afl/afl_sweep.py` runs inputs through the modes and reports aborts plus how much code executed
(where each input stopped: static skip, compile error, deploy, calls). Run it over a corpus sample after any harness change (false-positive check),
and over bug reproducers to see which modes catch them:

```bash
tools/afl/afl_sweep.py --sample 600 -o sweep corpus_afl
tools/afl/afl_sweep.py --build build_old -o sweep_pocs pocs/   # build_old: same harness, older solc
```

## Regression tests

`tools/afl/tests/inputs/*.sol` pin past false-positive fixes (each must
exit 0): `tools/afl/tests/run.sh`. Add inputs with a header comment
explaining what they exercise.
