#!/usr/bin/env bash
# Launch afl-fuzz against sol_afl_diff_runner.
#
# Self-contained: uses the vendored AFLplusplus/afl-fuzz and afl-ts
# (afl-ts/libts.so) plus the vendored tree-sitter-solidity grammar.
# Build them all with `cmake --build build` (default `make` target builds
# aflplusplus + afl_ts + tree_sitter_solidity automatically).
#
# Usage
# -----
#   tools/afl/run_afl.sh [findings_dir]
#
# Environment overrides
# ---------------------
#   JOBS=<n>                      Fan out across n cores: 1 AFL master (-M) plus
#                                 n-1 secondaries (-S), all syncing through the
#                                 findings dir, each in its own tmux window
#                                 (session "afl_diff"). Default 1 = single
#                                 foreground instance (unchanged).
#   MODE=<runner name>            Oracle mode binary (default: sol_afl_diff_runner_viair).
#   HARNESS=path/to/binary        Override the runner path entirely.
#   CORPUS=path/to/corpus_dir     Default: corpus_afl/
#   AFL_FUZZ_BIN=path/to/afl-fuzz Default: AFLplusplus/afl-fuzz (vendored).
#   AFL_TS_LIB=path/to/libts.so   Default: afl-ts/libts.so (vendored).
#                                 Set to empty to disable afl-ts and fall back
#                                 to AFL++'s built-in byte-level mutation.
#   TS_GRAMMAR=path/to/parser.so  Default: tree-sitter-solidity/libtree-sitter-solidity.so.
#                                 Override to point at a different grammar.
#   AFL_TIMEOUT_MS=1000           Per-input timeout. Slow inputs are recorded
#                                 as hangs in findings_afl/<fuzzer>/hangs/ and
#                                 the campaign continues — they are not crashes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Oracle mode: sol_afl_diff_runner (legacy vs legacy-opt), _viair (legacy-opt vs ir-opt), _viair_opt,
# _ssacfg, _optseq, _evmversion, or sol_afl_ice_runner (compile only, ICEs crash).
MODE="${MODE:-sol_afl_diff_runner_viair}"
HARNESS="${HARNESS:-$REPO_ROOT/build_afl/tools/afl/$MODE}"
CORPUS="${CORPUS:-$REPO_ROOT/corpus_afl}"
FINDINGS="${1:-$REPO_ROOT/findings_afl_${MODE#sol_afl_}}"
AFL_FUZZ_BIN="${AFL_FUZZ_BIN:-$REPO_ROOT/AFLplusplus/afl-fuzz}"
AFL_TS_LIB="${AFL_TS_LIB-$REPO_ROOT/afl-ts/libts.so}"
TS_GRAMMAR="${TS_GRAMMAR-$REPO_ROOT/tree-sitter-solidity/libtree-sitter-solidity.so}"
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-1000}"

if [[ ! -x "$HARNESS" ]]; then
    echo "ERROR: harness not found at $HARNESS" >&2
    echo "  Build first: tools/afl/build_instrumented.sh" >&2
    echo "  (or set HARNESS=path/to/uninstrumented/binary and add -n to run dumb-mode)" >&2
    exit 1
fi
if [[ ! -d "$CORPUS" ]] || [[ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]]; then
    echo "ERROR: corpus dir $CORPUS missing or empty" >&2
    echo "  Build first: $REPO_ROOT/tools/afl/build_corpus.sh" >&2
    exit 1
fi
if [[ ! -x "$AFL_FUZZ_BIN" ]]; then
    echo "ERROR: $AFL_FUZZ_BIN not found or not executable" >&2
    echo "  Build first: cmake --build $REPO_ROOT/build --target aflplusplus" >&2
    exit 1
fi

# afl-ts integration. Both the mutator .so and the grammar .so default to
# their vendored locations; the user can disable afl-ts entirely with
# AFL_TS_LIB= (empty).
declare -a AFL_TS_ENV=()
if [[ -n "$AFL_TS_LIB" ]]; then
    if [[ ! -f "$AFL_TS_LIB" ]]; then
        echo "ERROR: AFL_TS_LIB not found at $AFL_TS_LIB" >&2
        echo "  Build first: cmake --build $REPO_ROOT/build --target afl_ts" >&2
        exit 1
    fi
    if [[ ! -f "$TS_GRAMMAR" ]]; then
        echo "ERROR: TS_GRAMMAR not found at $TS_GRAMMAR" >&2
        echo "  Build first: cmake --build $REPO_ROOT/build --target tree_sitter_solidity" >&2
        exit 1
    fi
    AFL_TS_ENV+=(
        "AFL_CUSTOM_MUTATOR_LIBRARY=$AFL_TS_LIB"
        "TS_GRAMMAR=$TS_GRAMMAR"
        # nowarp.io recommend disabling byte-level mutation when an AST
        # mutator is loaded: byte mutations rarely help and clutter coverage.
        "AFL_CUSTOM_MUTATOR_ONLY=1"
    )
    echo "Using afl-ts custom mutator: $AFL_TS_LIB (grammar: $TS_GRAMMAR)"
else
    echo "afl-ts disabled (AFL_TS_LIB empty) — using AFL++'s built-in mutators."
fi

# Skip the CPU-governor check. AFL++ refuses to start unless the governor
# is "performance"; our default is "schedutil" / "powersave" on most distros.
# The proper fix is `sudo cpupower frequency-set -g performance` (~5% speedup);
# absent that, skip-the-check lets fuzzing run at the cost of slightly noisier
# timing. AFL_SKIP_CRASHES=0 (default) is fine — the core_pattern note in the
# README is the only real prereq.
AFL_TS_ENV+=("AFL_SKIP_CPUFREQ=1")
# Only save hangs that are still slow at 10 s on re-run (execs still time out at -t).
AFL_TS_ENV+=("AFL_HANG_TMOUT=${AFL_HANG_TMOUT:-10000}")

mkdir -p "$FINDINGS"

# Flags:
#   -t <ms>     per-input timeout. Inputs taking longer are recorded as hangs
#               (findings_afl/<fuzzer>/hangs/) and the campaign continues —
#               they are NOT escalated to crashes. Slow optimiser paths are
#               legion at the high end and aren't bugs we care about, so 1s
#               is a deliberate "skip the slow stuff" threshold.
#   -m none     no memory cap. solc + evmone allocate aggressively.
#
# No `@@` filename: the harness runs in AFL++ persistent + shared-memory mode
# (see sol_afl_diff_runner.cpp's main()), so AFL hands inputs over via the
# shared-memory ring rather than via a per-iteration file.
echo "Launching afl-fuzz against $HARNESS"
echo "  Corpus:    $CORPUS"
echo "  Findings:  $FINDINGS"
echo "  Timeout:   ${AFL_TIMEOUT_MS}ms"

JOBS="${JOBS:-1}"
if [[ "$JOBS" -le 1 ]]; then
    exec env "${AFL_TS_ENV[@]}" \
        "$AFL_FUZZ_BIN" \
            -i "$CORPUS" \
            -o "$FINDINGS" \
            -t "$AFL_TIMEOUT_MS" \
            -m none \
            -- "$HARNESS"
fi

# Parallel: 1 master (-M) + (JOBS-1) secondaries (-S), all syncing through
# $FINDINGS, each in its own tmux window. AFL auto-binds each instance to a free
# core. Build a shell-quoted env prefix so the mutator/grammar vars survive
# inside the tmux command strings even if a tmux server with a stale environment
# is already running.
command -v tmux >/dev/null || { echo "ERROR: JOBS>1 needs tmux" >&2; exit 1; }
ENVX=""
for kv in "${AFL_TS_ENV[@]}"; do ENVX+=" $(printf '%q' "$kv")"; done
SESSION="afl_diff"

run_one() {  # $1 = -M|-S, $2 = instance id, $3 = new-session|new-window
    local role="$1" id="$2" mode="$3"
    local cmd="env${ENVX} $(printf '%q' "$AFL_FUZZ_BIN") -i $(printf '%q' "$CORPUS") -o $(printf '%q' "$FINDINGS") $role $(printf '%q' "$id") -t $(printf '%q' "$AFL_TIMEOUT_MS") -m none -- $(printf '%q' "$HARNESS"); exec ${SHELL:-/bin/sh}"
    if [[ "$mode" == new-session ]]; then
        tmux new-session -d -s "$SESSION" -n "$id" "$cmd"
    else
        tmux new-window -t "$SESSION" -n "$id" "$cmd"
    fi
}

run_one -M m00 new-session
for ((i = 1; i < JOBS; i++)); do
    run_one -S "$(printf 's%02d' "$i")" new-window
done
tmux select-window -t "$SESSION:m00"
echo "launched $JOBS afl-fuzz instances (1 master + $((JOBS - 1)) secondaries) in tmux session '$SESSION'"
echo "attach:  tmux attach -t $SESSION       (switch windows: Ctrl-b n / Ctrl-b p)"
echo "status:  $REPO_ROOT/AFLplusplus/afl-whatsup $FINDINGS"
echo "stop:    tmux kill-session -t $SESSION"
