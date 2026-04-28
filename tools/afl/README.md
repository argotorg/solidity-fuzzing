# AFL Fuzzers

## Executables generated

- `solfuzzer` (from `solfuzzer.cpp`). Original AFL-based fuzzer that reads
  Solidity source from stdin or a file, compiles it, and signals a failure on
  internal errors. Supports `--standard-json` (test via JSON interface),
  `--const-opt` (test the constant optimizer), and `--without-optimizer` modes.
  Built by the normal (non-ossfuzz) cmake build.

- `sol_afl_diff_runner` (from `sol_afl_diff_runner.cpp`). AFL++ harness for
  *differential* Solidity fuzzing against EVMOne, modelled on
  `sol_proto_ossfuzz_evmone`. Reads a `.sol` file from `argv[1]` or stdin,
  compiles the last contract under two optimiser settings (`minimal` vs
  `standard`), deploys both, calls each with calldata bytes derived
  deterministically from the source (`keccak256(source)`), and `solAssert`s
  that status / output / logs / storage / transient storage match. On any
  mismatch the unhandled exception triggers `terminate()` → SIGABRT, which
  AFL++ records as a crash. Built by the normal (host) cmake build.

## sol_afl_diff_runner workflow

The pipeline is inspired by [nowarp.io's compiler-fuzzing
post](https://nowarp.io/blog/compiler-testing-part-1/), with two changes:
that work was crash-only (find ICEs), this is differential (also catches
silent miscompiles between optimiser configurations).

```bash
# 1. Build the AFL-instrumented harness in build_afl/ (separate from the
#    regular build/ tree). Uses afl-clang-fast for libsolc + harness;
#    evmone is built with stock clang as a workaround for an AFL++ wrapper
#    bug — solc gets full coverage feedback, evmone does not.
tools/afl/build_instrumented.sh

# 2. (Optional) Pull real-world Solidity projects into realworld_cache/
#    — OpenZeppelin, Aave, Solady, Uniswap v3/v4, Safe, ENS, etc. Adds
#    ~1800 contracts on top of the ~6800 from solidity/test/. Only needed
#    once; idempotent on re-run.
tools/afl/fetch_realworld.sh

# 3. Build the seed corpus. Always reads solidity/test/; also reads
#    realworld_cache/ if it exists.
tools/afl/build_corpus.sh                         # writes corpus_afl/
# or: MAX_BYTES=8192 tools/afl/build_corpus.sh    # smaller cap

# 4. Launch AFL++ (coverage-guided — instrumented binary at build_afl/).
tools/afl/run_afl.sh                              # writes findings_afl/
```

The repo now has three parallel build trees, one per toolchain:

| Tree              | Compiler            | Used for                                |
| ---               | ---                 | ---                                     |
| `build/`          | host gcc/clang      | `solc`, debug runners, reproducing      |
| `build_afl/`      | `afl-clang-fast`    | this AFL workflow                        |
| `build_ossfuzz/`  | clang+libc++ (Docker) | OSS-Fuzz / libFuzzer fuzzers          |

They never share object files. You can rebuild any one without touching the others.

When `run_afl.sh` finds a crash, the offending input lands in
`findings_afl/default/crashes/`. Replay it directly:

```bash
build/tools/afl/sol_afl_diff_runner findings_afl/default/crashes/id:000000,...
# Or use the existing debug runner for human-readable diff output:
build/tools/runners/sol_debug_runner findings_afl/default/crashes/id:000000,... --output-dir crash_dump
```

### Plugging in afl-ts (AST-aware mutator)

[`afl-ts`](https://github.com/nowarp/afl-ts) is an AFL++ custom-mutator
library that mutates inputs at the tree-sitter AST level (subtree splice,
sibling swap, typed-bank insertion etc.) — strictly better than byte-level
mutation for grammar-heavy targets like Solidity.

The Solidity tree-sitter grammar is vendored as a submodule at
`tree-sitter-solidity/`
([JoranHonig/tree-sitter-solidity](https://github.com/JoranHonig/tree-sitter-solidity)
— the de-facto Solidity grammar; same one nowarp.io used). Initialise it,
then either let cmake build it (it's part of the default `make` target) or
invoke the upstream Makefile directly:

```bash
git submodule update --init tree-sitter-solidity
make -C build tree_sitter_solidity        # via cmake (also runs as part of plain `make`)
# or, without cmake:
tools/afl/build_grammar.sh                # delegates to upstream's Makefile
# Either path produces tree-sitter-solidity/libtree-sitter-solidity.so
```

Then point afl-ts at the prebuilt afl-ts mutator library; `TS_GRAMMAR`
defaults to the vendored grammar so you don't need to set it:

```bash
AFL_TS_LIB=/path/to/libafl_ts.so tools/afl/run_afl.sh
```

`run_afl.sh` automatically sets `AFL_CUSTOM_MUTATOR_ONLY=1` when afl-ts is
loaded, disabling byte-level mutation per nowarp.io's guidance.

## Follow-ups (intentionally out of scope for the first cut)

- **Instrument evmone too.** Currently evmone is built with stock clang
  because the `afl-clang-fast++` wrapper double-wraps `-Wl,-soname,...`
  when linking shared libs (cmake 3.27+ × AFL++ interaction). solc IS
  instrumented, so most bugs we hunt are still findable. Two ways forward:
  (a) wait for AFL++ to fix the wrapper; (b) switch evmone to a static
  archive linked directly into the harness, bypassing the shared-lib link
  path entirely (also drops the dlopen + RPATH dance — cleaner long-term).

- **Persistent mode.** Add the `__AFL_LOOP(N)` loop around the harness body
  so each forked instance handles many inputs. ~10× iteration speed-up vs
  fork-mode but requires care: every `runOnce` must leave no global state
  behind (currently `yul::YulStringRepository::reset()` is called once at
  startup; it would need to move inside the loop).

- **`afl-cmin` corpus minimization.** Once the harness is instrumented,
  minimize `corpus_afl/` to drop redundant entries:
  `afl-cmin -i corpus_afl -o corpus_min -- ./sol_afl_diff_runner @@`.

- **`tsgen` corpus expansion.** Pull
  [`tsgen`](https://github.com/jubnzv/tsgen) and run it against a Solidity
  tree-sitter grammar to fill grammar surface that real-world contracts
  skip. nowarp.io got ~1300 unique <1 KB seeds for Solidity from 150k
  generated files post-minimization.

- **Identifier renaming.** Rewrite identifiers in corpus entries to
  deterministic names (`v0`, `v1`, ...) so afl-ts splices don't reliably
  generate "undeclared variable" errors, which gate fuzzer progress in the
  AST-mutation regime. Requires a tree-sitter pass on each entry.

- **Exercise multiple methods.** Currently the harness sends one calldata
  blob per run. Calling each public method of the deployed contract in
  sequence (still under one harness invocation) would multiply coverage per
  iteration without changing the corpus.

- **Cross-viaIR mode.** Mirror the `FUZZER_MODE_VIAIR` axis from the proto
  fuzzer: also run with `viaIR=true` vs `viaIR=false` to catch mismatches
  between the legacy and IR codegen paths.

- **Known non-bug filter parity.** Match `sol_proto_ossfuzz_evmone`'s
  ICE-swallowing list as it evolves. Current list copied verbatim; rebase
  if the proto fuzzer adds new entries.
