#!/usr/bin/env bash
# Launch a multi-core AFL++ campaign in a tmux session.
#
# AFL++ has no built-in -j N flag — parallelism means N separate afl-fuzz
# processes sharing one -o directory (corpus syncs automatically). This
# script automates that: 1 main + (N-1) secondaries, each in its own tmux
# pane with the vendored afl-ts mutator loaded and a varied AFL_* env-var
# combo so different cores explore different paths.
#
# Usage
# -----
#   tools/afl/run_afl_parallel.sh                 # auto: nproc - 1 cores
#   tools/afl/run_afl_parallel.sh -j 8            # 8 cores total
#   tools/afl/run_afl_parallel.sh -j 8 mycampaign # custom findings dir
#
# Attach when ready:
#   tmux attach -t solfuzz
# Stop the campaign:
#   tmux kill-session -t solfuzz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${HARNESS:-$REPO_ROOT/build_afl/tools/afl/sol_afl_diff_runner}"
CORPUS="${CORPUS:-$REPO_ROOT/corpus_afl}"
AFL_FUZZ_BIN="${AFL_FUZZ_BIN:-$REPO_ROOT/AFLplusplus/afl-fuzz}"
AFL_TS_LIB="${AFL_TS_LIB-$REPO_ROOT/afl-ts/libts.so}"
TS_GRAMMAR="${TS_GRAMMAR-$REPO_ROOT/tree-sitter-solidity/libtree-sitter-solidity.so}"
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-2000}"
SESSION="${SESSION:-solfuzz}"

JOBS=""
FINDINGS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -j) JOBS="$2"; shift 2 ;;
        -j*) JOBS="${1#-j}"; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) FINDINGS="$1"; shift ;;
    esac
done

[[ -n "$JOBS" ]] || JOBS=$(( $(nproc) - 1 ))
(( JOBS >= 1 )) || JOBS=1
FINDINGS="${FINDINGS:-$REPO_ROOT/findings_afl}"

# Pre-flight (same checks as run_afl.sh, plus tmux + watch for the dashboard).
command -v tmux  >/dev/null 2>&1 || { echo "ERROR: tmux not in PATH." >&2; exit 1; }
command -v watch >/dev/null 2>&1 || { echo "ERROR: watch not in PATH (procps-ng package)." >&2; exit 1; }
[[ -x "$HARNESS"      ]] || { echo "ERROR: harness missing: $HARNESS"        >&2; echo "  tools/afl/build_instrumented.sh" >&2; exit 1; }
[[ -d "$CORPUS"       ]] || { echo "ERROR: corpus dir missing: $CORPUS"      >&2; echo "  tools/afl/build_corpus.sh"        >&2; exit 1; }
[[ -x "$AFL_FUZZ_BIN" ]] || { echo "ERROR: afl-fuzz missing: $AFL_FUZZ_BIN"  >&2; echo "  make -C build aflplusplus"        >&2; exit 1; }
if [[ -n "$AFL_TS_LIB" ]]; then
    [[ -f "$AFL_TS_LIB" ]] || { echo "ERROR: afl-ts missing: $AFL_TS_LIB"   >&2; echo "  make -C build afl_ts"        >&2; exit 1; }
    [[ -f "$TS_GRAMMAR" ]] || { echo "ERROR: grammar missing: $TS_GRAMMAR"  >&2; echo "  make -C build tree_sitter_solidity" >&2; exit 1; }
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "ERROR: tmux session '$SESSION' already exists." >&2
    echo "  Attach: tmux attach -t $SESSION" >&2
    echo "  Kill:   tmux kill-session -t $SESSION" >&2
    exit 1
fi

# Per-secondary env-var diversification. Each gets a different power schedule
# (-p) plus an AFL++ behaviour flag so different cores explore different
# paths instead of all running the same strategy. Cycles when JOBS is large.
SECONDARY_PROFILES=(
    "-p fast    AFL_DISABLE_TRIM=1"
    "-p coe     AFL_KEEP_TIMEOUTS=1"
    "-p lin     AFL_EXPAND_HAVOC_NOW=1"
    "-p quad    AFL_CMPLOG_ONLY_NEW=1"
    "-p exploit AFL_DISABLE_TRIM=1"
    "-p rare    AFL_KEEP_TIMEOUTS=1"
    "-p mmopt   AFL_EXPAND_HAVOC_NOW=1"
)

# Build the env-var prefix that every pane shares.
# AFL_SKIP_CPUFREQ: AFL++ refuses to start unless the CPU governor is
# "performance"; setting this lets fuzzing run at the cost of slightly
# noisier timing. The proper fix is `sudo cpupower frequency-set -g performance`.
declare -a TS_ENV=(AFL_SKIP_CPUFREQ=1)
if [[ -n "$AFL_TS_LIB" ]]; then
    TS_ENV+=(
        "AFL_CUSTOM_MUTATOR_LIBRARY=$AFL_TS_LIB"
        "TS_GRAMMAR=$TS_GRAMMAR"
        AFL_CUSTOM_MUTATOR_ONLY=1
    )
fi
COMMON_FLAGS=(-i "$CORPUS" -o "$FINDINGS" -t "$AFL_TIMEOUT_MS" -m none)

mkdir -p "$FINDINGS"

# Build the shell command each tmux pane runs. The trailing `; bash` keeps
# the pane open after afl-fuzz exits so the user can read any error.
build_pane_cmd() {
    local instance_args="$1"
    local extra_env="$2"
    local env_str=""
    for kv in "${TS_ENV[@]}"; do env_str+=" $kv"; done
    [[ -n "$extra_env" ]] && env_str+=" $extra_env"
    echo "cd '$REPO_ROOT' && env$env_str '$AFL_FUZZ_BIN' $instance_args ${COMMON_FLAGS[*]} -- '$HARNESS' @@; echo; echo '[afl-fuzz exited — Ctrl-D to close pane]'; bash"
}

# Top-of-session dashboard pane: `watch afl-whatsup` gives a live
# aggregate view (execs/sec across all fuzzers, paths, crashes, hangs)
# that AFL++ doesn't otherwise provide — afl-fuzz's per-process TUI only
# shows that one process. Refreshes every 5 s.
AFL_WHATSUP="${AFL_FUZZ_BIN%/*}/afl-whatsup"
DASHBOARD_CMD="while [[ ! -d '$FINDINGS' ]] || [[ -z \"\$(ls -A '$FINDINGS' 2>/dev/null)\" ]]; do sleep 1; done; watch -n 5 -t '$AFL_WHATSUP' -d '$FINDINGS'"

# Pane 0 — dashboard.
tmux new-session -d -s "$SESSION" -n fuzz "$DASHBOARD_CMD"

# Pane 1 — main fuzzer (deterministic + havoc, default schedule).
MAIN_CMD=$(build_pane_cmd "-M main" "")
tmux split-window -t "$SESSION:fuzz" "$MAIN_CMD"

# Panes 2..JOBS — secondaries, each with a rotated profile.
for ((i=1; i<JOBS; i++)); do
    profile_idx=$(( (i - 1) % ${#SECONDARY_PROFILES[@]} ))
    profile="${SECONDARY_PROFILES[$profile_idx]}"
    sched_flag=$(echo "$profile" | awk '{print $1, $2}')   # "-p fast"
    extra_env=$(echo "$profile" | awk '{$1=$2=""; print $0}' | sed 's/^[[:space:]]*//')
    SEC_CMD=$(build_pane_cmd "-S sec$i $sched_flag" "$extra_env")
    tmux split-window -t "$SESSION:fuzz" "$SEC_CMD"
    # Re-tile after every split so panes stay roughly equal size.
    tmux select-layout -t "$SESSION:fuzz" tiled >/dev/null
done

echo "Started AFL++ campaign in tmux session: $SESSION"
echo "  Cores:    $JOBS (1 main + $((JOBS-1)) secondaries)"
echo "  Findings: $FINDINGS"
[[ -n "$AFL_TS_LIB" ]] && echo "  Mutator:  afl-ts (grammar: $TS_GRAMMAR)"
echo
echo "Attach:  tmux attach -t $SESSION"
echo "Status:  $REPO_ROOT/AFLplusplus/afl-whatsup $FINDINGS"
echo "Stop:    tmux kill-session -t $SESSION"
