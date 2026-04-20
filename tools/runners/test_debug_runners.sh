#!/usr/bin/env bash
# Test suite for sol_debug_runner and yul_debug_runner.
#
# Usage:
#   tools/runners/test_debug_runners.sh ./build
#
# The runners embed an RPATH to libevmone.so when EVMONE_LIB_DIR was set at
# configure time, so LD_LIBRARY_PATH is usually not needed. If your build
# did not set it, prepend it explicitly:
#   LD_LIBRARY_PATH=/path/to/evmone/lib:$LD_LIBRARY_PATH \
#     tools/runners/test_debug_runners.sh ./build
#
# Filename convention for expected exit codes:
#   *_match.*        -> expect exit 0 (all configs match)
#   *_mismatch.*     -> expect exit 1 (differential mismatch)
#   *_compilefail.*  -> expect exit 2 (compilation failure)
#   *_iceerror.*     -> expect exit 3 (internal compiler error)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_CASES_DIR="${SCRIPT_DIR}/test_cases"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <build-dir>"
    echo "  e.g.: $0 ./build"
    exit 2
fi

BUILD_DIR="$(cd "$1" && pwd)"
SOL_RUNNER="${BUILD_DIR}/tools/runners/sol_debug_runner"
YUL_RUNNER="${BUILD_DIR}/tools/runners/yul_debug_runner"

# Verify binaries exist
for bin in "$SOL_RUNNER" "$YUL_RUNNER"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: $bin not found or not executable"
        exit 2
    fi
done

# Derive expected exit code from filename
expected_exit_code() {
    local name="$1"
    case "$name" in
        *_match.*)      echo 0 ;;
        *_mismatch.*)   echo 1 ;;
        *_compilefail.*) echo 2 ;;
        *_iceerror.*)   echo 3 ;;
        *)
            echo "ERROR: Cannot determine expected exit code from filename: $name" >&2
            echo "  Use suffix: _match, _mismatch, _compilefail, or _iceerror" >&2
            exit 2
            ;;
    esac
}

passed=0
failed=0
skipped=0
failures=()

run_test() {
    local runner="$1"
    local testfile="$2"
    local name
    name="$(basename "$testfile")"
    local expected
    expected="$(expected_exit_code "$name")"

    local actual=0
    "$runner" "$testfile" --quiet >/dev/null 2>&1 || actual=$?

    if [[ "$actual" -eq "$expected" ]]; then
        echo "  PASS: $name"
        ((++passed))
    else
        echo "  FAIL: $name (expected exit $expected, got $actual)"
        ((++failed))
        failures+=("$name (expected $expected, got $actual)")
    fi
}

# Run .sol tests
echo "=== sol_debug_runner tests ==="
sol_count=0
for f in "${TEST_CASES_DIR}/sol/"*.sol; do
    [[ -f "$f" ]] || continue
    run_test "$SOL_RUNNER" "$f"
    ((++sol_count))
done
if [[ "$sol_count" -eq 0 ]]; then
    echo "  (no .sol test cases found)"
fi
echo

# Run .yul tests
echo "=== yul_debug_runner tests ==="
yul_count=0
for f in "${TEST_CASES_DIR}/yul/"*.yul; do
    [[ -f "$f" ]] || continue
    run_test "$YUL_RUNNER" "$f"
    ((++yul_count))
done
if [[ "$yul_count" -eq 0 ]]; then
    echo "  (no .yul test cases found)"
fi
echo

# Summary
total=$((passed + failed))
echo "=== Summary: $passed/$total passed ==="
if [[ ${#failures[@]} -gt 0 ]]; then
    echo "Failures:"
    for f in "${failures[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
exit 0
