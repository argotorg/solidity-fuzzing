#!/usr/bin/env bash
# Generate a Solidity seed corpus from the tree-sitter grammar via tsgen
# (https://github.com/jubnzv/tsgen). tsgen walks the grammar recursively
# and emits syntactically-structured programs — useful for hitting grammar
# surface that real-world contracts skip (obscure modifier combinations,
# deeply-nested expressions, rarely-used type literals, etc.).
#
# Pipeline:
#   1. Build tsgen via cargo (one-shot, ~30 s).
#   2. Run tsgen against tree-sitter-solidity/src/grammar.json with
#      libtree-sitter-solidity.so for parser-level validation. Output goes
#      to corpus_tsgen_raw/ as `*.sol`.
#   3. Drop entries larger than $MAX_BYTES (default 1024) — nowarp.io's
#      reference run kept only <1 KB seeds.
#   4. If an instrumented harness is built (build_afl/) and afl-cmin is
#      available, minimize the surviving entries to corpus_tsgen/ keeping
#      only those that add coverage. Without instrumentation, the size-
#      filtered entries land in corpus_tsgen/ directly.
#
# Usage:
#   tools/afl/build_corpus_tsgen.sh                # writes to corpus_tsgen/
#   tools/afl/build_corpus_tsgen.sh /tmp/my_seeds  # custom output dir
#   COUNT=150000 COVERAGE_TARGET=0.0 \              # match nowarp.io's run
#       tools/afl/build_corpus_tsgen.sh             # (hard count, no early stop)
#   MAX_BYTES=2048 tools/afl/build_corpus_tsgen.sh # relax size cap
#   SKIP_CMIN=1 tools/afl/build_corpus_tsgen.sh    # skip minimization
#
# Note: COUNT is a *floor*. tsgen keeps generating until both COUNT and
# COVERAGE_TARGET (default 0.95) are satisfied. With the default target,
# even COUNT=10 produces a few thousand files because grammar coverage
# rises slowly. Set COVERAGE_TARGET=0.0 to make COUNT a hard stop.
#
# To merge into the regular AFL corpus:
#   cp corpus_tsgen/* corpus_afl/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TSGEN_DIR="$REPO_ROOT/tsgen"
GRAMMAR_DIR="$REPO_ROOT/tree-sitter-solidity"
GRAMMAR_JSON="$GRAMMAR_DIR/src/grammar.json"
GRAMMAR_SO="$GRAMMAR_DIR/libtree-sitter-solidity.so"
TSGEN_BIN="$TSGEN_DIR/target/release/tsgen"

OUT="${1:-$REPO_ROOT/corpus_tsgen}"
RAW_OUT="${OUT}_raw"
COUNT="${COUNT:-2000}"
MAX_BYTES="${MAX_BYTES:-1024}"
SEED="${SEED:-0}"
MAX_DEPTH="${MAX_DEPTH:-15}"
MAX_REPEAT="${MAX_REPEAT:-5}"
COVERAGE_TARGET="${COVERAGE_TARGET:-0.95}"

# --- Pre-flight: submodules + grammar artefacts ---
if [[ ! -f "$TSGEN_DIR/Cargo.toml" ]]; then
    echo "ERROR: tsgen submodule missing. Run: git submodule update --init tsgen" >&2
    exit 1
fi
if [[ ! -f "$GRAMMAR_JSON" ]]; then
    echo "ERROR: $GRAMMAR_JSON not found. Run: git submodule update --init tree-sitter-solidity" >&2
    exit 1
fi
if [[ ! -f "$GRAMMAR_SO" ]]; then
    echo "Building libtree-sitter-solidity.so..."
    make -C "$GRAMMAR_DIR" libtree-sitter-solidity.so
fi

# --- Build tsgen if needed ---
if [[ ! -x "$TSGEN_BIN" ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
        echo "ERROR: cargo not found. Install rustup or apt install cargo." >&2
        exit 1
    fi
    echo "Building tsgen (cargo build --release)..."
    cargo build --release --manifest-path "$TSGEN_DIR/Cargo.toml"
fi

# --- Generate ---
rm -rf "$RAW_OUT"
mkdir -p "$RAW_OUT"
echo "Generating $COUNT programs into $RAW_OUT/ ..."
"$TSGEN_BIN" \
    --grammar "$GRAMMAR_JSON" \
    --parser "$GRAMMAR_SO" \
    --count "$COUNT" \
    --coverage-target "$COVERAGE_TARGET" \
    --output-dir "$RAW_OUT" \
    --ext .sol \
    --seed "$SEED" \
    --max-depth "$MAX_DEPTH" \
    --max-repeat "$MAX_REPEAT"

raw_total=$(find "$RAW_OUT" -type f -name '*.sol' | wc -l)
echo "tsgen produced $raw_total files."

# --- Size filter (in place: delete entries over the cap) ---
removed=0
while IFS= read -r -d '' f; do
    sz=$(stat -c%s "$f")
    if (( sz == 0 || sz > MAX_BYTES )); then
        rm -f "$f"
        removed=$((removed + 1))
    fi
done < <(find "$RAW_OUT" -type f -name '*.sol' -print0)
kept=$((raw_total - removed))
echo "Size filter (<= $MAX_BYTES bytes): kept $kept, dropped $removed."

# --- Optional cmin minimization against the instrumented harness ---
HARNESS="$REPO_ROOT/build_afl/tools/afl/sol_afl_diff_runner"
AFL_CMIN="$REPO_ROOT/AFLplusplus/afl-cmin"
mkdir -p "$OUT"
rm -rf "$OUT"/*

if [[ -z "${SKIP_CMIN:-}" && -x "$HARNESS" && -x "$AFL_CMIN" ]]; then
    echo "Minimizing with afl-cmin (this can take a while)..."
    AFL_SKIP_CPUFREQ=1 "$AFL_CMIN" \
        -i "$RAW_OUT" \
        -o "$OUT" \
        -t 2000 -m none \
        -- "$HARNESS" @@
    final=$(find "$OUT" -type f | wc -l)
    echo
    echo "Wrote $final unique-coverage seeds to $OUT/"
    echo "Raw outputs (pre-cmin) kept at $RAW_OUT/."
else
    if [[ -n "${SKIP_CMIN:-}" ]]; then
        echo "SKIP_CMIN set — skipping minimization."
    else
        echo "afl-cmin or instrumented harness not found — skipping minimization."
        echo "  AFL build:    make -C build aflplusplus && tools/afl/build_instrumented.sh"
    fi
    cp "$RAW_OUT"/*.sol "$OUT"/ 2>/dev/null || true
    final=$(find "$OUT" -type f | wc -l)
    echo
    echo "Wrote $final size-filtered seeds to $OUT/"
fi
