# AFL differential `.sol` fuzzer

`sol_afl_diff_runner` reads a `.sol` file, compiles + deploys the last
contract under two optimiser settings (minimal vs standard), calls each
with calldata derived from the source, and `solAssert`s that status /
output / logs / storage match. A mismatch aborts (SIGABRT) and AFL records
a crash. Runs in AFL++ persistent mode; a filename arg replays a single
input for triage (no AFL runtime needed).

Sources containing `assembly` or `gas()` are skipped — they legitimately
differ across optimiser settings.

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
tools/afl/build_corpus.sh          # -> corpus_afl/
tools/afl/build_corpus_tsgen.sh    # grammar-driven extra surface
cp corpus_tsgen/*.sol corpus_afl/

tools/afl/run_afl.sh               # single core (afl-ts mutator)
tools/afl/run_afl_parallel.sh -j 8 # tmux: 1 main + N-1 secondaries
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

## Regression tests

`tools/afl/tests/inputs/*.sol` pin past false-positive fixes (each must
exit 0): `tools/afl/tests/run.sh`. Add inputs with a header comment
explaining what they exercise.
