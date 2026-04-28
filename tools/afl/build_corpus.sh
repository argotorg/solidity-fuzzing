#!/usr/bin/env bash
# Build a seed corpus for sol_afl_diff_runner from the solidity submodule's
# test suite. Files are copied to $OUT, deduplicated by SHA-256, and capped at
# $MAX_BYTES so afl-fuzz doesn't waste cycles on huge inputs.
#
# Usage:
#   tools/afl/build_corpus.sh                 # writes to corpus_afl/
#   tools/afl/build_corpus.sh /tmp/my_corpus  # custom output dir
#
# Follow-ups to layer on later (out of scope for the early implementation):
#   * afl-cmin -i corpus_afl -o corpus_min -- ./sol_afl_diff_runner @@
#     to drop entries that don't add coverage. Requires the harness built
#     with afl-clang-fast for instrumentation feedback.
#   * tsgen invocation against a Solidity tree-sitter grammar to fill grammar
#     surface that real-world contracts skip (see https://github.com/jubnzv/tsgen).
#   * Identifier renaming pass (v0, v1, ...) to suppress "undeclared variable"
#     errors that block fuzzer progress (technique from nowarp.io's blog).
#   * Strip per-test annotation comments (// ==== / // ----) so the corpus
#     contains only the source bodies the compiler actually sees.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOL_TEST_DIR="$REPO_ROOT/solidity/test"
OUT="${1:-$REPO_ROOT/corpus_afl}"
MAX_BYTES="${MAX_BYTES:-16384}"

if [[ ! -d "$SOL_TEST_DIR" ]]; then
    echo "ERROR: $SOL_TEST_DIR does not exist — initialize the solidity submodule first." >&2
    echo "  git submodule update --init --recursive" >&2
    exit 1
fi

mkdir -p "$OUT"

# Sources to draw from. semanticTests and compilationTests are the most
# valuable: real, compiling contracts that actually exercise codegen. The
# others contribute syntax variety. afl-fuzz happily ignores entries that
# don't compile, so we err on the inclusive side here and let afl-cmin
# minimize later if needed.
SUBDIRS=(
    libsolidity/semanticTests
    libsolidity/syntaxTests
    libsolidity/smtCheckerTests
    libsolidity/lsp
    cmdlineTests
    compilationTests
)

added=0
skipped_size=0
skipped_dup=0

declare -A seen_hash

for sub in "${SUBDIRS[@]}"; do
    src="$SOL_TEST_DIR/$sub"
    [[ -d "$src" ]] || continue
    while IFS= read -r -d '' f; do
        size=$(stat -c%s "$f")
        if (( size == 0 || size > MAX_BYTES )); then
            skipped_size=$((skipped_size + 1))
            continue
        fi
        h=$(sha256sum "$f" | cut -d' ' -f1)
        if [[ -n "${seen_hash[$h]:-}" ]]; then
            skipped_dup=$((skipped_dup + 1))
            continue
        fi
        seen_hash[$h]=1
        # Flatten path so the filename is a recognisable origin marker.
        rel="${f#$SOL_TEST_DIR/}"
        flat="${rel//\//__}"
        cp "$f" "$OUT/$flat"
        added=$((added + 1))
    done < <(find "$src" -name '*.sol' -print0)
done

echo "Wrote $added files to $OUT"
echo "  Skipped (size > $MAX_BYTES or empty): $skipped_size"
echo "  Skipped (duplicate content):          $skipped_dup"
