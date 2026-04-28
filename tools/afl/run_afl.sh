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
#   HARNESS=path/to/binary        Override sol_afl_diff_runner location
#                                 (default: build_afl/tools/afl/sol_afl_diff_runner).
#   CORPUS=path/to/corpus_dir     Default: corpus_afl/
#   AFL_FUZZ_BIN=path/to/afl-fuzz Default: AFLplusplus/afl-fuzz (vendored).
#   AFL_TS_LIB=path/to/libts.so   Default: afl-ts/libts.so (vendored).
#                                 Set to empty to disable afl-ts and fall back
#                                 to AFL++'s built-in byte-level mutation.
#   TS_GRAMMAR=path/to/parser.so  Default: tree-sitter-solidity/libtree-sitter-solidity.so.
#                                 Override to point at a different grammar.
#   AFL_TIMEOUT_MS=2000           Per-input timeout (compiler runs slow).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${HARNESS:-$REPO_ROOT/build_afl/tools/afl/sol_afl_diff_runner}"
CORPUS="${CORPUS:-$REPO_ROOT/corpus_afl}"
FINDINGS="${1:-$REPO_ROOT/findings_afl}"
AFL_FUZZ_BIN="${AFL_FUZZ_BIN:-$REPO_ROOT/AFLplusplus/afl-fuzz}"
AFL_TS_LIB="${AFL_TS_LIB-$REPO_ROOT/afl-ts/libts.so}"
TS_GRAMMAR="${TS_GRAMMAR-$REPO_ROOT/tree-sitter-solidity/libtree-sitter-solidity.so}"
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-2000}"

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

mkdir -p "$FINDINGS"

# Flags:
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
        -- "$HARNESS" @@
