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

### Vendored toolchain — everything's a submodule

The full AFL++ toolchain plus the AST-aware mutator are vendored:

| Submodule              | Source                                         | Built artefact                                         |
| ---                    | ---                                            | ---                                                    |
| `AFLplusplus/`         | github.com/AFLplusplus/AFLplusplus             | `afl-fuzz`, `afl-clang-fast{,++}`, `afl-cmin`          |
| `afl-ts/`              | github.com/jubnzv/afl-ts                       | `libts.so` (AFL++ custom-mutator library, AST splice)  |
| `tree-sitter-solidity/`| github.com/JoranHonig/tree-sitter-solidity     | `libtree-sitter-solidity.so` (parser; loaded by afl-ts) |

All three build as part of the default `make` target in `build/`:

```bash
git submodule update --init --recursive
cmake -S . -B build && make -C build -j$(nproc)
```

Need a single one rebuilt? `make -C build aflplusplus` (or `afl_ts`,
`tree_sitter_solidity`).

`run_afl.sh` defaults to using all three: the vendored `afl-fuzz` runs the
campaign, `libts.so` is loaded as the custom mutator, and
`libtree-sitter-solidity.so` is the grammar. To disable afl-ts and fall
back to byte-level mutation:

```bash
AFL_TS_LIB= tools/afl/run_afl.sh
```

### One-time system setup

AFL++ has two pre-flight checks that fail by default on most modern Linux
distros:

**1. Kernel `core_pattern` must not pipe to a coredump handler.** Required
(no opt-out for real campaigns):

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
```

**2. CPU governor should be `performance`.** Both `run_afl.sh` and
`run_afl_parallel.sh` set `AFL_SKIP_CPUFREQ=1` so AFL++ proceeds with
whatever governor you have, but for ~5-10% throughput improvement on a
real campaign:

```bash
sudo cpupower frequency-set -g performance
# Restore later with: sudo cpupower frequency-set -g schedutil   (or whatever you had)
```

### Parallel fuzzing

AFL++ has no built-in `-j N` flag — parallelism means *N separate
afl-fuzz processes* sharing one `-o` directory (corpus syncs
automatically). For one-command multi-core use:

```bash
tools/afl/run_afl_parallel.sh                 # auto: nproc - 1 cores
tools/afl/run_afl_parallel.sh -j 8            # specific core count
tools/afl/run_afl_parallel.sh -j 8 my_run     # custom findings dir
```

This spawns N+1 *windows* (not panes — each gets the full terminal width
so the afl-fuzz TUIs aren't cramped) in a tmux session named `solfuzz`:

- **Window `dashboard`** — `watch -n 5 afl-whatsup` showing live aggregate
  stats (execs/sec across all fuzzers, paths, crashes, hangs). AFL++ has
  no built-in unified TUI, only one-shot text snapshots and per-process
  TUIs; this fills that gap.
- **Window `main`** — main fuzzer (`-M main`, default schedule).
- **Windows `sec1`, `sec2`, ...** — secondaries rotating through different
  power schedules + AFL++ behaviour flags so cores explore different paths
  instead of duplicating work.

Switch between windows with `Ctrl-b n` (next), `Ctrl-b p` (prev),
`Ctrl-b <N>` (jump to window N), or `Ctrl-b w` (interactive list). The
session opens on the dashboard.

```bash
tmux attach -t solfuzz                        # watch the panes
AFLplusplus/afl-whatsup findings_afl          # aggregate status
tmux kill-session -t solfuzz                  # stop the campaign
```

If you'd rather drive the processes by hand, the manual recipe is below
— `run_afl_parallel.sh` does exactly this for you.

Every `afl-fuzz` invocation needs the afl-ts env vars (they don't inherit
between instances) and uses the vendored binary. Set the env once per
shell so the lines below stay readable:

```bash
export AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/afl-ts/libts.so
export TS_GRAMMAR=$PWD/tree-sitter-solidity/libtree-sitter-solidity.so
export AFL_CUSTOM_MUTATOR_ONLY=1
```

Then:

```bash
# Terminal 1 — main (deterministic + havoc):
AFLplusplus/afl-fuzz -M main -i corpus_afl -o findings_afl -t 2000 -m none \
    -- build_afl/tools/afl/sol_afl_diff_runner @@

# Terminals 2..N — secondaries (havoc-only). Per-secondary env vars below
# diversify mutation strategies so different cores explore different paths:
AFL_DISABLE_TRIM=1     AFLplusplus/afl-fuzz -S sec1 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner @@
AFL_KEEP_TIMEOUTS=1    AFLplusplus/afl-fuzz -S sec2 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner @@
AFL_EXPAND_HAVOC_NOW=1 AFLplusplus/afl-fuzz -S sec3 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner @@
AFL_CMPLOG_ONLY_NEW=1  AFLplusplus/afl-fuzz -S sec4 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner @@
```

Live aggregate status across all instances:

```bash
AFLplusplus/afl-whatsup findings_afl
```

A `-j N` flag for `run_afl.sh` that spawns tmux panes for 1 main + N-1
secondaries (matching `tools/ossfuzz/README.md`'s parallel pattern) is on
the follow-up list below.

## Follow-ups (intentionally out of scope for the first cut)

- **Instrument evmone too.** Currently evmone is built with stock clang
  because the `afl-clang-fast++` wrapper double-wraps `-Wl,-soname,...`
  when linking shared libs (cmake 3.27+ × AFL++ interaction). solc IS
  instrumented, so most bugs we hunt are still findable. Two ways forward:
  (a) wait for AFL++ to fix the wrapper; (b) switch evmone to a static
  archive linked directly into the harness, bypassing the shared-lib link
  path entirely (also drops the dlopen + RPATH dance — cleaner long-term).

- **`-j N` parallel launcher.** Extend `run_afl.sh` to spawn 1 main + N-1
  secondaries in a `tmux` session, varying the AFL++ env vars listed
  above across secondaries. Matches the parallel pattern documented in
  `tools/ossfuzz/README.md` for single-pass yul fuzzing.

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
