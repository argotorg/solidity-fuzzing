#!/bin/bash
# Dump Solidity files from a fuzzer corpus and check them for compilation
# errors and feature diversity.
#
# Usage:
#   ./tools/runners/check_diversity_and_errors.sh <corpus_dir> <num_files> [fuzzer_binary]
#
# Examples:
#   ./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone 300
#   ./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone 300 ./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone
#   ./tools/runners/check_diversity_and_errors.sh my_corpus_sol_proto_ossfuzz_evmone_viair 300 ./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone_viair

set -eu

CORPUS_DIR="${1:?Usage: $0 <corpus_dir> <num_files> [fuzzer_binary]}"
NUM_FILES="${2:?Usage: $0 <corpus_dir> <num_files> [fuzzer_binary]}"
FUZZER_BIN="${3:-./build_ossfuzz/tools/ossfuzz/sol_proto_ossfuzz_evmone}"
SOLC="./build/solc/solc"
CHECK_SCRIPT="./tools/ossfuzz/check_sol_proto_files.py"
DUMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/check_diversity_XXXXXX")

if [ ! -d "$CORPUS_DIR" ]; then
    echo "Error: corpus directory '$CORPUS_DIR' not found" >&2
    exit 1
fi

if [ ! -x "$FUZZER_BIN" ]; then
    echo "Error: fuzzer binary '$FUZZER_BIN' not found or not executable" >&2
    exit 1
fi

if [ ! -x "$SOLC" ]; then
    echo "Warning: solc binary '$SOLC' not found, compilation checks will fail" >&2
fi

total_in_corpus=$(find "$CORPUS_DIR" -maxdepth 1 -type f | wc -l)

echo "============================================================"
echo "  check_diversity_and_errors.sh"
echo "============================================================"
echo "  Corpus dir:     $CORPUS_DIR ($total_in_corpus files)"
echo "  Sampling:       $NUM_FILES files"
echo "  Fuzzer binary:  $FUZZER_BIN"
echo "  Solc binary:    $SOLC"
echo "  Dump dir:       $DUMP_DIR"
echo "  Check script:   $CHECK_SCRIPT"
echo "============================================================"
echo

# Step 1: dump .sol files from randomly selected corpus entries
echo "Step 1/3: Selecting $NUM_FILES random corpus entries and dumping .sol files..."
echo "  Running: find ... | shuf -n $NUM_FILES | fuzzer -> $DUMP_DIR/*.sol"
dumped=0
find "$CORPUS_DIR" -maxdepth 1 -type f -print0 \
  | shuf -z -n "$NUM_FILES" \
  | while IFS= read -r -d '' file; do
      PROTO_FUZZER_DUMP_PATH="$DUMP_DIR/$(basename "$file").sol" \
        "$FUZZER_BIN" "$file" 2>/dev/null || true
      dumped=$((dumped + 1))
      # Progress every 50 files
      if [ $((dumped % 50)) -eq 0 ]; then
          echo "  ... dumped $dumped files"
      fi
    done

actual=$(find "$DUMP_DIR" -name "*.sol" | wc -l)
echo "  Done. Dumped $actual .sol files to $DUMP_DIR"
echo

# Step 2: compile and check features
echo "Step 2/3: Compiling with solc and tallying features..."
echo "  Running: python3 $CHECK_SCRIPT $DUMP_DIR --solc $SOLC"
echo
python3 "$CHECK_SCRIPT" "$DUMP_DIR" --solc "$SOLC"

echo "Done. Dumped .sol files are in: $DUMP_DIR"
echo "To clean up: rm -rf $DUMP_DIR"
