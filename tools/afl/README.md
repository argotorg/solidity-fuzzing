# AFL Fuzzers

## Executables generated

- `solfuzzer` (from `solfuzzer.cpp`). Original AFL-based fuzzer that reads
  Solidity source from stdin or a file, compiles it, and signals a failure on
  internal errors. Supports `--standard-json` (test via JSON interface),
  `--const-opt` (test the constant optimizer), and `--without-optimizer` modes.
  Built by the normal (non-ossfuzz) cmake build.

- `sol_afl_diff_runner` (from `sol_afl_diff_runner.cpp`). AFL++ harness for
  *differential* Solidity fuzzing against EVMOne, modelled on
  `sol_proto_ossfuzz_evmone`. Runs in AFL++ **persistent + shared-memory
  mode** ([README.persistent_mode.md](../../AFLplusplus/instrumentation/README.persistent_mode.md)):
  one process handles up to 1000 inputs before AFL re-forks, amortising
  libsolc / libevmone startup for a ~10–20× speed-up over fork-per-input.
  For each input, the harness compiles the last contract under two
  optimiser settings (`minimal` vs `standard`), deploys both, calls each
  with calldata bytes derived deterministically from the source
  (`keccak256(source)`), and `solAssert`s that status / output / logs /
  storage / transient storage match. On any mismatch the unhandled
  exception triggers `terminate()` → SIGABRT, which AFL++ records as a
  crash and then re-forks the persistent child for the next input.
  Sources containing the substring `assembly` or `gas()` are skipped
  wholesale — inline-asm blocks regularly violate solc's documented
  invariants in ways the differential oracle mistakes for optimiser
  mismatches, and gas() observations legitimately differ between
  optimiser configurations.

  **Repro / triage** still works: `./sol_afl_diff_runner path/to/crash`
  bypasses the persistent loop entirely (the filename arg short-circuits
  before `__AFL_INIT()`), so a host build without an AFL runtime can
  still replay a single input for debugging.

## sol_afl_diff_runner workflow

The pipeline is inspired by [nowarp.io's compiler-fuzzing
post](https://nowarp.io/blog/compiler-testing-part-1/), with two changes:
that work was crash-only (find ICEs), this is differential (also catches
silent miscompiles between optimiser configurations).

See [the main README](../../README.md#running-the-afl-differential-fuzzer)
for build / corpus / launch commands and troubleshooting. Three build
trees coexist (`build/` host gcc, `build_afl/` afl-clang-fast,
`build_ossfuzz/` Docker clang+libc++) and never share object files —
rebuild any one without touching the others. The AFL build instruments
libsolc, evmone, and the harness; evmone is built as a static archive
(`libevmone-standalone.a`) and linked directly to sidestep an
afl-clang-fast++ wrapper bug that mangles `-Wl,-soname` when linking
shared libs.

### Vendored toolchain — everything's a submodule

The full AFL++ toolchain plus the AST-aware mutator are vendored:

| Submodule              | Source                                         | Built artefact                                         |
| ---                    | ---                                            | ---                                                    |
| `AFLplusplus/`         | github.com/AFLplusplus/AFLplusplus             | `afl-fuzz`, `afl-clang-fast{,++}`, `afl-cmin`          |
| `afl-ts/`              | github.com/msooseth/afl-ts (`region-aware`)    | `libts.so` (AFL++ custom-mutator library, AST splice)  |
| `tree-sitter-solidity/`| github.com/JoranHonig/tree-sitter-solidity     | `libtree-sitter-solidity.so` (parser; loaded by afl-ts) |
| `tsgen/`               | github.com/jubnzv/tsgen                        | `tsgen` (Rust; grammar-based corpus generator, on demand) |

The `afl-ts` submodule is a fork of upstream `jubnzv/afl-ts` carrying one
patch: when the input ends with the magic suffix `[u16 LE source_len][0xCA 0xFE]`,
the mutator parses and splices only the leading source slice through
tree-sitter, leaving the calldata bytes and trailer untouched. AFL's
regular havoc / bit-flipping then mutates the calldata region freely.
See [Input format and afl-ts integration](#input-format-and-afl-ts-integration)
below.

`tree_sitter_solidity` builds as part of the default `make` target (small,
no extra deps). `aflplusplus` and `afl_ts` are **opt-in** via explicit
targets — building AFL++ takes minutes and needs `clang` + `llvm-dev`
that non-AFL CI / users shouldn't be forced to install:

```bash
git submodule update --init --recursive
cmake -S . -B build
make -C build -j$(nproc)                      # solc, host harness, grammar
make -C build -j$(nproc) aflplusplus afl_ts   # the AFL toolchain (when ready to fuzz)
```

`tools/afl/build_afl.sh` wraps the cmake + make steps above as a single
invocation. `tools/afl/build_instrumented.sh` checks that both binaries
exist and prints the exact command above if not.

`run_afl.sh` defaults to using all three: the vendored `afl-fuzz` runs the
campaign, `libts.so` is loaded as the custom mutator, and
`libtree-sitter-solidity.so` is the grammar. To disable afl-ts and fall
back to byte-level mutation:

```bash
AFL_TS_LIB= tools/afl/run_afl.sh
```

### Input format and afl-ts integration

Two input shapes are accepted by `sol_afl_diff_runner`:

**1. Plain Solidity source.** Whole file is treated as Solidity. Calldata
sent to the deployed contract is `keccak256(source)[:32]` — fixed for a
given source. This is the original format and existing pure-`.sol`
corpus entries continue to work unchanged.

**2. Region-aware format** (used together with the patched `afl-ts`):

```
[ source bytes ][ calldata bytes ][ u16 LE source_len ][ 0xCA 0xFE ]
```

The trailing `0xCA 0xFE` magic + length prefix tells both the harness
*and* afl-ts where the source ends. The harness sends the calldata bytes
to the deployed contract directly. The patched afl-ts (in our fork)
parses only the leading `source_len` bytes through tree-sitter and
preserves the trailer verbatim, so AFL's regular havoc / bit-flipping —
which AFL runs in addition to the custom mutator — naturally mutates
the calldata region without afl-ts splicing over it.

Net effect on a queue entry that uses the format:

| Mutation pass     | Source bytes      | Calldata + trailer |
| ---               | ---               | ---                |
| `afl-ts custom`   | AST splice        | preserved verbatim |
| AFL deterministic | byte-level havoc  | byte-level havoc   |
| AFL havoc/splice  | byte-level havoc  | byte-level havoc   |

If AFL deterministic stages happen to flip bits inside the magic itself,
the format check fails on that exec — the harness falls back to plain
mode (calldata = keccak256(source)). That's a feature: those flips
naturally explore the with-calldata / without-calldata axis. Empirically
~90–97% of queue entries retain an intact trailer.

`tools/afl/build_corpus.sh` seeds `SEED_CALLDATA_COUNT` (default 200)
random entries with the new format using common ERC-style function
selectors (`a9059cbb` transfer, `70a08231` balanceOf, etc.) plus 32
argument bytes. Set `SEED_CALLDATA_COUNT=0` to skip if you want a
purely pre-existing-shape corpus.

### Grammar-driven corpus expansion via tsgen

Real-world contracts cluster around a narrow grammar surface — common
ERC patterns, a handful of statement shapes, a usual small set of type
literals. Whole regions of the Solidity grammar (rare modifiers, exotic
tuple/type-expression shapes, deeply-nested ternaries, …) are entirely
absent from the test-suite + real-world corpus produced by
`build_corpus.sh`. [tsgen](https://github.com/jubnzv/tsgen) (vendored as
a submodule) walks a tree-sitter grammar and emits syntactically-valid
programs to fill that gap. Reference run from
[nowarp.io](https://nowarp.io/blog/compiler-testing-part-1/): ~150 k
generated Solidity files, minimised to ~1300 unique <1 KB seeds.

```bash
# Default: ~thousands of files, all <= 1 KB, optionally cmin-minimised
# against the AFL-instrumented harness if build_afl/ exists.
tools/afl/build_corpus_tsgen.sh                  # writes to corpus_tsgen/

# Match nowarp.io's run (hard count, no early stop on coverage):
COUNT=150000 COVERAGE_TARGET=0.0 tools/afl/build_corpus_tsgen.sh

# Merge into the main corpus once you're happy:
cp corpus_tsgen/* corpus_afl/
```

The script: builds tsgen (`cargo build --release` — needs `cargo`),
runs it against `tree-sitter-solidity/src/grammar.json` with the
compiled parser for validation, drops entries over `MAX_BYTES`
(default 1024), then runs `afl-cmin` against
`build_afl/tools/afl/sol_afl_diff_runner` to keep only coverage-
unique entries. If the AFL build isn't present, minimisation is
skipped and the size-filtered set is emitted as-is. Set `SKIP_CMIN=1`
to skip minimisation explicitly.

`COUNT` is a *floor* — tsgen keeps generating until both that count and
`COVERAGE_TARGET` (default 0.95) are satisfied. Even `COUNT=10` produces
several thousand files because grammar coverage rises slowly. Set
`COVERAGE_TARGET=0.0` to make `COUNT` a hard stop.

Caveat: tsgen only enforces *parse* validity, not semantic validity —
many emitted programs reference undeclared identifiers, mismatched
types, or non-existent imports and fail at compile time. That's fine for
afl-ts splice material (we want diverse AST fragments, not standalone
deployable contracts) but means tsgen outputs help less when used as
literal seeds without further mutation. The "Identifier renaming"
follow-up below targets the same problem from the other direction.

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
# Terminal 1 — main (deterministic + havoc). No `@@`: the harness runs in
# AFL++ persistent + shared-memory mode, so AFL hands inputs over via the
# shared-memory ring rather than via a per-iteration file path.
AFLplusplus/afl-fuzz -M main -i corpus_afl -o findings_afl -t 2000 -m none \
    -- build_afl/tools/afl/sol_afl_diff_runner

# Terminals 2..N — secondaries (havoc-only). Per-secondary env vars below
# diversify mutation strategies so different cores explore different paths:
AFL_DISABLE_TRIM=1     AFLplusplus/afl-fuzz -S sec1 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner
AFL_KEEP_TIMEOUTS=1    AFLplusplus/afl-fuzz -S sec2 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner
AFL_EXPAND_HAVOC_NOW=1 AFLplusplus/afl-fuzz -S sec3 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner
AFL_CMPLOG_ONLY_NEW=1  AFLplusplus/afl-fuzz -S sec4 -i corpus_afl -o findings_afl -t 2000 -m none -- build_afl/tools/afl/sol_afl_diff_runner
```

Live aggregate status across all instances:

```bash
AFLplusplus/afl-whatsup findings_afl
```

A `-j N` flag for `run_afl.sh` that spawns tmux panes for 1 main + N-1
secondaries (matching `tools/ossfuzz/README.md`'s parallel pattern) is on
the follow-up list below.

### Triaging crashes and hangs

Crashes land in `findings_afl/<fuzzer>/crashes/`, hangs in
`findings_afl/<fuzzer>/hangs/`. Both follow the AFL++ filename convention:

```
id:000003,sig:06,src:000523,time:18342,execs:128193,op:havoc,rep:8
```

`sig:06` = SIGABRT, the only signal the harness raises (one of the
`solAssert`s in the diff oracle fired).

#### Replaying a crash

For real debugging use `sol_debug_runner --afl` — it understands the same
input format `sol_afl_diff_runner` does (region-aware trailer + keccak
fallback) and runs all four optimiser × viaIR configurations with
human-readable per-config diffs of status / output / logs / storage /
transient storage, plus written-out bytecodes and Yul IR:

```bash
build/tools/runners/sol_debug_runner --afl findings_afl/sec1/crashes/id:000003,...
# Exit codes: 0 = all match, 1 = mismatch found, 2 = compile failure, 3 = ICE.
# Per-config bytecode/IR/log files land in sol_debug_output-N/.
```

`sol_afl_diff_runner` is still useful as a one-line ground-truth check
that the crash *still* reproduces with the exact harness AFL ran. It's
silent on success and aborts on diff (no diagnostic output beyond the
`solAssert` message), so prefer the debug runner once you've confirmed
the crash is real:

```bash
build/tools/afl/sol_afl_diff_runner findings_afl/sec1/crashes/id:000003,...
echo "exit=$?"   # 134 = SIGABRT (real diff); 0 = no longer reproduces
```

To group crashes by which assertion fired (status / output / logs /
storage / transient / revert data) — useful because AFL syncs the same
crash across secondaries so 9 files often = 1 unique bug:

```bash
for f in findings_afl/*/crashes/id:*; do
    { build/tools/afl/sol_afl_diff_runner "$f"; } 2>&1 \
        | grep "Sol AFL diff fuzzer" | head -1
done | sort | uniq -c | sort -rn
```

#### Hangs are inputs that exceeded `-t 2000`

A "hang" doesn't mean an infinite loop — it means **the harness took
longer than the 2-second timeout**. AFL measures against a calibration
baseline taken at fuzzer startup; under varying system load the baseline
drifts, so many hangs don't reproduce when re-run solo. Pathological
inputs (genuine DoS candidates) DO reproduce and are visibly slow.

To time every hang and find the genuinely slow ones:

```bash
for f in findings_afl/*/hangs/id:*; do
    elapsed=$( { /usr/bin/time -f '%e' \
                  timeout 30 build/tools/afl/sol_afl_diff_runner "$f" \
                    >/dev/null 2>&1; } 2>&1 )
    sz=$(stat -c%s "$f")
    printf "%6s s   %6d B   %s\n" "$elapsed" "$sz" "$(basename "$f")"
done | sort -rn | head -10
```

Rule of thumb on the resulting times:
- `< 2 s`: borderline, was timing-sensitive. Ignore unless reproducible.
- `2–10 s`: slow optimiser path. Worth a glance, rarely a real bug.
- `> 30 s` (timeout cap): potential DoS. Worth filing.

#### Profiling a slow input with solc directly

If `perf record` on the harness shows the time is in the compiler (not in
evmone or the diff oracle), reproduce the same compilation pipeline with
the standalone `solc` — easier to attach a profiler to, and isolates the
slowdown from the deploy/call/diff path. The harness compiles each input
twice with `viaIR=false`, EVM version `current()`, once with
`OptimiserSettings::minimal()` and once with `OptimiserSettings::standard()`:

```bash
# fast leg (minimal — usually not the culprit):
time build/solidity/solc/solc --bin --evm-version prague <hang-file>

# slow leg (standard — almost certainly where the time goes):
time build/solidity/solc/solc --bin --optimize --evm-version prague <hang-file>
```

Caveats so the comparison is honest:
- `EVMVersion::current()` in the harness is the newest version solc knows
  about; solc CLI's default is usually one or two behind. Check
  `solc --help | grep -A1 evm-version` and pass that value explicitly.
- `viaIR=false` is the CLI default — do **not** pass `--via-ir`.
- The harness picks only the last contract (`lastContractName()`); the CLI
  compiles every contract. If the file has many contracts, strip all but
  the last for an apples-to-apples comparison.
- `--optimize-runs` defaults to 200, which matches what
  `OptimiserSettings::standard()` uses — no need to tune it.
- If the input is `> 16 KB` the harness exits early
  (`s_maxSourceBytes` in `sol_afl_diff_runner.cpp`); solc has no such cap.

#### Minimising a real reproducer

When a crash reproduces, shrink it with `afl-tmin` before filing:

```bash
AFLplusplus/afl-tmin \
    -i findings_afl/sec1/crashes/id:000003,... \
    -o min.sol \
    -- build_afl/tools/afl/sol_afl_diff_runner
build/tools/runners/sol_debug_runner --afl min.sol   # human-readable diff
```

Without `--afl`, `sol_debug_runner` looks up `test()` on a contract called
`C` (matching the proto fuzzer). With `--afl` it deploys the *last*
contract in the source and sends the AFL calldata raw, matching what
`sol_afl_diff_runner` does — so any AFL crash file (corpus contracts named
arbitrarily, with or without the `0xCA 0xFE` trailer) reproduces directly.

## Follow-ups (intentionally out of scope for the first cut)

- **`afl-cmin` corpus minimization.** Once the harness is instrumented,
  minimize `corpus_afl/` to drop redundant entries:
  `afl-cmin -i corpus_afl -o corpus_min -- ./sol_afl_diff_runner`.

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
