#!/usr/bin/env bash
# Build a seed corpus for sol_afl_diff_runner from:
#   * the solidity submodule's test suite (always)
#   * realworld_cache/  (if present — populated by tools/afl/fetch_realworld.sh)
#
# Files are copied to $OUT, deduplicated by SHA-256 across both sources, and
# capped at $MAX_BYTES so afl-fuzz doesn't waste cycles on huge inputs.
#
# Usage:
#   tools/afl/build_corpus.sh                 # writes to corpus_afl/
#   tools/afl/build_corpus.sh /tmp/my_corpus  # custom output dir
#   MAX_BYTES=8192 tools/afl/build_corpus.sh  # smaller cap
#
# Follow-ups (deliberately out of scope for the early implementation):
#   * afl-cmin -i corpus_afl -o corpus_min -- ./sol_afl_diff_runner @@
#     to drop entries that don't add coverage. Requires the harness built
#     with afl-clang-fast for instrumentation feedback.
#   * tsgen invocation against tree-sitter-solidity to fill grammar surface
#     that real-world contracts skip (see https://github.com/jubnzv/tsgen).
#   * Identifier renaming pass (v0, v1, ...) to suppress "undeclared variable"
#     errors that block fuzzer progress (technique from nowarp.io's blog).
#   * Strip per-test annotation comments (// ==== / // ----) so the corpus
#     contains only the source bodies the compiler actually sees.
#   * Strip / inline `import` directives in real-world entries so more of
#     them are individually compilable (currently many fail at compile time
#     and are usable only as AST splice material).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOL_TEST_DIR="$REPO_ROOT/solidity/test"
REALWORLD_DIR="$REPO_ROOT/realworld_cache"
OUT="${1:-$REPO_ROOT/corpus_afl}"
MAX_BYTES="${MAX_BYTES:-16384}"

mkdir -p "$OUT"

# Shared dedupe + counters across all sources.
declare -A seen_hash
added=0
skipped_size=0
skipped_dup=0
skipped_oracle=0

# Pattern that catches Solidity / Yul features whose values legitimately
# differ across optimiser levels — comparing them in the diff oracle is a
# false positive ("the optimised code burned different gas").
#   gasleft( | .gas: | {gas: | tx.gasprice
#   msize / pc / codesize / gas as Yul opcodes (inside assembly blocks)
# We filter at the file level (anywhere in the source) — slightly over-
# inclusive (a Solidity variable named "msize" gets dropped too) but far
# safer than letting one slip through.
ORACLE_UNSAFE_REGEX='\bgasleft[[:space:]]*\(|\bmsize\b|\bcodesize\b|\.gas[[:space:]]*:|\{[[:space:]]*gas[[:space:]]*:|tx\.gasprice|\bgasprice\b'

# Path components we never want to walk into. Catches typical JS/Foundry/
# Hardhat build outputs and re-vendored dependency trees that would just add
# duplicates of OZ etc.
EXCLUDE_DIRS=(
    .git node_modules lib_imports lib_dependencies node_modules_lib
    out cache artifacts coverage typechain typechain-types
    .next .yarn .pnpm-store dist build target
)

# Build a `find` predicate that skips $EXCLUDE_DIRS.
build_find_excludes() {
    local args=()
    for d in "${EXCLUDE_DIRS[@]}"; do
        args+=( -name "$d" -prune -o )
    done
    args+=( -name '*.sol' -type f -print0 )
    printf '%s\0' "${args[@]}"
}

# Walk a directory tree, ingest .sol files into $OUT with dedupe + size cap.
# $1: source root  $2: filename prefix (becomes part of the flattened name)
ingest_tree() {
    local src="$1"
    local prefix="$2"
    [[ -d "$src" ]] || return 0
    local args=()
    for d in "${EXCLUDE_DIRS[@]}"; do
        args+=( -name "$d" -prune -o )
    done
    args+=( -name '*.sol' -type f -print0 )
    while IFS= read -r -d '' f; do
        local size
        size=$(stat -c%s "$f")
        if (( size == 0 || size > MAX_BYTES )); then
            skipped_size=$((skipped_size + 1))
            continue
        fi
        if grep -qE "$ORACLE_UNSAFE_REGEX" "$f" 2>/dev/null; then
            skipped_oracle=$((skipped_oracle + 1))
            continue
        fi
        local h
        h=$(sha256sum "$f" | cut -d' ' -f1)
        if [[ -n "${seen_hash[$h]:-}" ]]; then
            skipped_dup=$((skipped_dup + 1))
            continue
        fi
        seen_hash[$h]=1
        local rel="${f#$src/}"
        local flat="${prefix}__${rel//\//__}"
        cp "$f" "$OUT/$flat"
        added=$((added + 1))
    done < <(find "$src" \( "${args[@]}" \))
}

# --- Source 1: solidity submodule test suite ---
if [[ ! -d "$SOL_TEST_DIR" ]]; then
    echo "ERROR: $SOL_TEST_DIR does not exist — initialize the solidity submodule first." >&2
    echo "  git submodule update --init --recursive" >&2
    exit 1
fi

# Subset matters less than throughput here: afl-fuzz happily ignores entries
# that don't compile, and we dedupe by content. Walk the whole test tree.
SOL_TEST_SUBDIRS=(
    libsolidity/semanticTests
    libsolidity/syntaxTests
    libsolidity/smtCheckerTests
    libsolidity/lsp
    cmdlineTests
    compilationTests
)
for sub in "${SOL_TEST_SUBDIRS[@]}"; do
    ingest_tree "$SOL_TEST_DIR/$sub" "soltest_${sub//\//_}"
done

# --- Source 2: real-world contracts cache ---
if [[ -d "$REALWORLD_DIR" ]]; then
    for repo_dir in "$REALWORLD_DIR"/*/; do
        [[ -d "$repo_dir" ]] || continue
        repo_name=$(basename "$repo_dir")
        ingest_tree "${repo_dir%/}" "rw_${repo_name}"
    done
else
    echo "(realworld_cache/ not present — skipping. Run tools/afl/fetch_realworld.sh to populate.)"
fi

echo
echo "Wrote $added files to $OUT"
echo "  Skipped (size > $MAX_BYTES or empty):   $skipped_size"
echo "  Skipped (duplicate content):            $skipped_dup"
echo "  Skipped (oracle-unsafe gas/msize/pc):   $skipped_oracle"
