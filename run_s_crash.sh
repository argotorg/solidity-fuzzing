#!/usr/bin/env bash
# For each crash-<hash> in s_crash/:
#   1. Dump the protobuf to s_crash/crash-<hash>.yul via yul_proto_ossfuzz_evmone_single_pass_s
#   2. Replay it with yul_debug_runner --optimizer-sequence s --optimizer-cleanup-sequence ""
#      and save its output to s_crash/crash-<hash>.out
set -u

CRASH_DIR="s_crash"
DUMPER="./build_ossfuzz/tools/ossfuzz/yul_proto_ossfuzz_evmone_single_pass_s"
RUNNER="$(pwd)/build/tools/runners/yul_debug_runner"

if [[ ! -x "$DUMPER" ]]; then
    echo "missing: $DUMPER" >&2
    exit 1
fi
if [[ ! -x "$RUNNER" ]]; then
    echo "missing: $RUNNER" >&2
    exit 1
fi
if [[ ! -d "$CRASH_DIR" ]]; then
    echo "missing dir: $CRASH_DIR" >&2
    exit 1
fi

# Throwaway dir so the runner's yul_debug_output-N folders don't clutter cwd.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

total=0
done_count=0
skipped=0
for f in "$CRASH_DIR"/crash-*; do
    # Only raw crash files (no extension).
    base=$(basename "$f")
    [[ "$base" == *.* ]] && continue
    total=$((total + 1))
done

i=0
for f in "$CRASH_DIR"/crash-*; do
    base=$(basename "$f")
    [[ "$base" == *.* ]] && continue
    i=$((i + 1))

    yul_out="$CRASH_DIR/${base}.yul"
    run_out="$CRASH_DIR/${base}.out"

    if [[ -s "$yul_out" && -s "$run_out" ]]; then
        skipped=$((skipped + 1))
        continue
    fi

    printf '[%d/%d] %s ... ' "$i" "$total" "$base"

    # 1. Dump the protobuf to Yul. The fuzzer harness deliberately crashes
    # after dumping (libFuzzer "deadly signal"), so a non-zero exit is normal.
    PROTO_FUZZER_DUMP_PATH="$(pwd)/$yul_out" \
        "$DUMPER" "$f" >/dev/null 2>&1 || true

    if [[ ! -s "$yul_out" ]]; then
        echo "dump-failed"
        continue
    fi

    # 2. Replay through yul_debug_runner from a throwaway cwd so its
    # yul_debug_output-N artifacts are discarded.
    pushd "$WORK" >/dev/null
    rm -rf yul_debug_output-*
    "$RUNNER" --quiet \
        --optimizer-sequence s \
        --optimizer-cleanup-sequence "" \
        "$(dirs -l +1)/$yul_out" \
        >"$(dirs -l +1)/$run_out" 2>&1
    rc=$?
    popd >/dev/null

    done_count=$((done_count + 1))
    summary=$(head -n 1 "$run_out")
    echo "rc=$rc ${summary:-<empty>}"
done

echo
echo "done: $done_count processed, $skipped skipped (already had .yul + .out), $total total"
