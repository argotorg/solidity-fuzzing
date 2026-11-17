#!/usr/bin/env bash
# Launch a protobuf fuzzer under afl-fuzz with the matching LPM custom mutator.
#
#   tools/ossfuzz/run_ossfuzz_afl.sh <fuzzer> <corpus_dir> [findings_dir]
#   tools/ossfuzz/run_ossfuzz_afl.sh --resume <fuzzer> [findings_dir]
#
# <fuzzer> is the binary name under build_afl/tools/ossfuzz/, e.g.
# yul_proto_ossfuzz_evmone. The corpus dir must hold at least one non-empty
# seed. With --resume, AFL re-reads its own findings dir (afl-fuzz -i-) and
# continues from the existing queue — no corpus dir needed.
#
# Set JOBS=<n> to fan out across n cores: one AFL master (-M) plus n-1
# secondaries (-S), all syncing through the same findings dir, each in its own
# tmux window (session "afl_<fuzzer>"). JOBS=1 (default) runs a single instance
# in the foreground as before.
set -eu

ROOTDIR="$(realpath "$(dirname "$0")/../..")"

RESUME=0
if [ "${1:-}" = "--resume" ]; then RESUME=1; shift; fi

USAGE="usage: run_ossfuzz_afl.sh [--resume] <fuzzer> <corpus_dir> [findings_dir]"
FUZZER="${1:?$USAGE}"
if [ "$RESUME" -eq 1 ]; then
  INPUT="-"                          # AFL resume marker: re-read the findings dir
  FINDINGS="${2:-findings_${FUZZER}}"
else
  INPUT="${2:?need a corpus dir}"
  FINDINGS="${3:-findings_${FUZZER}}"
  # AFL aborts ("No usable test cases") on a missing or empty input dir, even
  # though the LPM custom mutator can grow a corpus from nothing. Drop in a
  # single seed so afl-fuzz has a queue entry to start mutating. The harness and
  # mutator use TEXT-format protobuf (DEFINE_PROTO_FUZZER's use_binary=false), so
  # the seed must be valid text format: a comment line is non-empty (AFL needs
  # that) yet parses to a default message — arbitrary bytes flood stderr with
  # "Error parsing text-format ... Program" instead.
  if [ ! -d "$INPUT" ] || [ -z "$(find "$INPUT" -maxdepth 1 -type f ! -empty -print -quit)" ]; then
    echo "seeding empty corpus dir: $INPUT" >&2
    mkdir -p "$INPUT"
    printf '# empty seed: valid text-format protobuf, parses to a default message\n' > "$INPUT/seed"
  fi
fi

# Map fuzzer -> grammar -> mutator .so.
case "$FUZZER" in
  yul_proto_ossfuzz_evmone*)                 base=yulProto ;;
  shuffler_proto_ossfuzz)                    base=shufflerProto ;;
  sol_recstruct_alias_ossfuzz)               base=solRecStructAliasProto ;;
  sol_roundtrip_ossfuzz)                     base=solRoundtripProto ;;
  abiv2_proto_ossfuzz)                       base=abiV2Proto ;;
  *) echo "unknown fuzzer: $FUZZER" >&2; exit 1 ;;
esac

export AFL_CUSTOM_MUTATOR_LIBRARY="${ROOTDIR}/deps_afl/lib/lib${base}_lpm_mutator.so"
export AFL_CUSTOM_MUTATOR_ONLY=1   # only the LPM grammar mutator, no byte havoc
export AFL_SKIP_CPUFREQ=1
# AFL trims new queue entries by chopping raw bytes, which bypasses the custom
# mutator and hands the harness a truncated text-format proto — flooding stderr
# with "Error parsing text-format ... Program". We don't implement the custom
# trim API, so just disable trimming; LPM keeps inputs minimal anyway.
export AFL_DISABLE_TRIM=1
# Execs still time out at -t 2000; a hang is only saved if it also exceeds this on re-run.
# At 2 s nearly every saved "hang" was just a slow-but-normal compile.
export AFL_HANG_TMOUT="${AFL_HANG_TMOUT:-10000}"

AFL="${ROOTDIR}/AFLplusplus/afl-fuzz"
BIN="${ROOTDIR}/build_afl/tools/ossfuzz/${FUZZER}"

JOBS="${JOBS:-1}"
if [ "$JOBS" -le 1 ]; then
  exec "$AFL" -i "$INPUT" -o "$FINDINGS" -m none -t 2000 -- "$BIN"
fi

# Parallel: 1 master (-M) + (JOBS-1) secondaries (-S), all syncing through
# $FINDINGS. Each runs in its own tmux window. AFL auto-binds each instance to a
# free core. Re-export the mutator env inside each command so it survives even if
# a tmux server with a stale environment is already running.
command -v tmux >/dev/null || { echo "JOBS>1 needs tmux" >&2; exit 1; }
ENVX="AFL_CUSTOM_MUTATOR_LIBRARY='$AFL_CUSTOM_MUTATOR_LIBRARY'"
ENVX="$ENVX AFL_CUSTOM_MUTATOR_ONLY=1 AFL_SKIP_CPUFREQ=1 AFL_DISABLE_TRIM=1 AFL_FAST_CAL=1 AFL_HANG_TMOUT=$AFL_HANG_TMOUT"
SESSION="afl_${FUZZER}"

tmux new-session -d -s "$SESSION" -n m00 \
  "env $ENVX '$AFL' -i '$INPUT' -o '$FINDINGS' -M m00 -m none -t 2000 -- '$BIN'; exec ${SHELL:-/bin/sh}"
for i in $(seq 1 $((JOBS - 1))); do
  id=$(printf 's%02d' "$i")
  tmux new-window -t "$SESSION" -n "$id" \
    "env $ENVX '$AFL' -i '$INPUT' -o '$FINDINGS' -S '$id' -m none -t 2000 -- '$BIN'; exec ${SHELL:-/bin/sh}"
done
tmux select-window -t "$SESSION:m00"
echo "launched $JOBS afl-fuzz instances (1 master + $((JOBS - 1)) secondaries) in tmux session '$SESSION'"
echo "attach:  tmux attach -t $SESSION       (switch windows: Ctrl-b n / Ctrl-b p)"
echo "status:  ${ROOTDIR}/AFLplusplus/afl-whatsup '$FINDINGS'"
echo "stop:    tmux kill-session -t $SESSION"
