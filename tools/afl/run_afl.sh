#!/usr/bin/env bash
# Launch afl-fuzz against sol_afl_diff_runner.
#
# This is a *thin* wrapper that captures the conventions worth standardising:
# corpus + findings dir layout, AFL++ flags appropriate for compiler-style
# targets (longer timeouts, no byte-level mutation when an AST mutator is
# loaded), and the env vars needed to plug in afl-ts as a custom mutator.
#
# Prerequisites
# -------------
#   * AFL++ installed (afl-fuzz, afl-cmin). NOT classic AFL — afl-ts is an
#     AFL++ custom-mutator-library extension.
#   * Build tree at build/ with sol_afl_diff_runner. The current binary is
#     NOT instrumented — afl-fuzz will run in dumb mode (-n). For real
#     coverage feedback, rebuild solc + evmone with afl-clang-fast (see
#     tools/afl/README.md TODO).
#   * Corpus prepared: tools/afl/build_corpus.sh (writes corpus_afl/).
#
# Usage
# -----
#   tools/afl/run_afl.sh [findings_dir]
#
# Optional environment overrides:
#   CORPUS=path/to/corpus_dir
#   AFL_TS_LIB=/path/to/libafl_ts.so
#       Loads afl-ts as the AFL++ custom mutator (https://github.com/nowarp/afl-ts).
#       When set, TS_GRAMMAR defaults to the vendored
#       tree-sitter-solidity/libtree-sitter-solidity.so — build it first with
#       tools/afl/build_grammar.sh. Override TS_GRAMMAR to point at a
#       different grammar.
#   AFL_FUZZ_BIN=afl-fuzz             Override afl-fuzz binary path.
#   AFL_TIMEOUT_MS=2000               Per-input timeout (compiler runs slow).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="$REPO_ROOT/build/tools/afl/sol_afl_diff_runner"
CORPUS="${CORPUS:-$REPO_ROOT/corpus_afl}"
FINDINGS="${1:-$REPO_ROOT/findings_afl}"
AFL_FUZZ_BIN="${AFL_FUZZ_BIN:-afl-fuzz}"
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-2000}"

if [[ ! -x "$HARNESS" ]]; then
    echo "ERROR: harness not found at $HARNESS" >&2
    echo "  Build first: cd build && make -j\$(nproc) sol_afl_diff_runner" >&2
    exit 1
fi
if [[ ! -d "$CORPUS" ]] || [[ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]]; then
    echo "ERROR: corpus dir $CORPUS missing or empty" >&2
    echo "  Build first: $REPO_ROOT/tools/afl/build_corpus.sh" >&2
    exit 1
fi
if ! command -v "$AFL_FUZZ_BIN" >/dev/null 2>&1; then
    echo "ERROR: $AFL_FUZZ_BIN not in PATH — install AFL++ (https://github.com/AFLplusplus/AFLplusplus)" >&2
    exit 1
fi

# afl-ts integration. Default TS_GRAMMAR to the vendored tree-sitter-solidity
# build if the user only set AFL_TS_LIB.
declare -a AFL_TS_ENV=()
if [[ -n "${AFL_TS_LIB:-}" ]]; then
    if [[ -z "${TS_GRAMMAR:-}" ]]; then
        TS_GRAMMAR="$REPO_ROOT/tree-sitter-solidity/libtree-sitter-solidity.so"
    fi
    if [[ ! -f "$TS_GRAMMAR" ]]; then
        echo "ERROR: TS_GRAMMAR not found at $TS_GRAMMAR" >&2
        echo "  Build it: $REPO_ROOT/tools/afl/build_grammar.sh" >&2
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
elif [[ -n "${TS_GRAMMAR:-}" ]]; then
    echo "WARNING: TS_GRAMMAR is set but AFL_TS_LIB is not — afl-ts won't be loaded." >&2
fi

mkdir -p "$FINDINGS"

# Flags:
#   -n          dumb mode — required because the harness isn't instrumented
#               with afl-clang-fast yet. Drop this once we ship an
#               instrumented build.
#   -t <ms>     per-input timeout. Compiler frontends are slow; default
#               1000ms timeouts are too tight.
#   -m none     no memory cap. solc + evmone allocate aggressively.
#   @@          AFL substitutes the input file path here.
echo "Launching afl-fuzz against $HARNESS"
echo "  Corpus:    $CORPUS"
echo "  Findings:  $FINDINGS"
echo "  Timeout:   ${AFL_TIMEOUT_MS}ms"
exec env "${AFL_TS_ENV[@]}" \
    "$AFL_FUZZ_BIN" \
        -i "$CORPUS" \
        -o "$FINDINGS" \
        -t "$AFL_TIMEOUT_MS" \
        -m none \
        -n \
        -- "$HARNESS" @@
