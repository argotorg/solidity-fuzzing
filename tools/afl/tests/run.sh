#!/usr/bin/env bash
# Regression test suite for the AFL Solidity diff runner
# (build/tools/afl/sol_afl_diff_runner). Each .sol input under inputs/
# must complete with exit code 0 — either passes the differential or is
# legitimately skipped (sub-call OOG, code-introspection false positive,
# etc.). A non-zero exit means the runner crashed via solAssert / SIGABRT,
# i.e. a regression in the harness skip logic.
#
# Add a new input by dropping a .sol into inputs/ and (briefly) describing
# at the top of the file what it exercises and why.
set -euo pipefail

cd "$(dirname "$0")/../../.."  # repo root

RUNNER="${RUNNER:-build/tools/afl/sol_afl_diff_runner}"
# viair_*.sol: legacy-vs-IR skips, which only that mode applies
RUNNER_VIAIR="${RUNNER_VIAIR:-build/tools/afl/sol_afl_diff_runner_viair}"
for r in "$RUNNER" "$RUNNER_VIAIR"; do
    if [[ ! -x "$r" ]]; then
        echo "runner not found: $r (build it with 'make -C build $(basename "$r")')" >&2
        exit 2
    fi
done

shopt -s nullglob
inputs=(tools/afl/tests/inputs/*.sol)
if [[ ${#inputs[@]} -eq 0 ]]; then
    echo "no test inputs under tools/afl/tests/inputs/" >&2
    exit 2
fi

fails=0
for f in "${inputs[@]}"; do
    runner="$RUNNER"
    [[ $(basename "$f") == viair_* ]] && runner="$RUNNER_VIAIR"
    if "$runner" "$f" >/dev/null 2>&1; then
        echo "PASS  $f"
    else
        rc=$?
        echo "FAIL  $f  (exit $rc)"
        fails=$((fails + 1))
    fi
done

if [[ $fails -eq 0 ]]; then
    echo "all ${#inputs[@]} test(s) passed"
    exit 0
else
    echo "$fails of ${#inputs[@]} test(s) failed" >&2
    exit 1
fi
