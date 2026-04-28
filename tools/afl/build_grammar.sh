#!/usr/bin/env bash
# Build the tree-sitter-solidity parser shared library used by afl-ts.
#
# The grammar lives in the tree-sitter-solidity/ submodule
# (https://github.com/JoranHonig/tree-sitter-solidity); upstream ships a
# Makefile that compiles src/parser.c into libtree-sitter-solidity.so. We
# just delegate to it so any future changes to the build (e.g. an external
# scanner) come along automatically.
#
# Output:
#   tree-sitter-solidity/libtree-sitter-solidity.so
#
# Use it with run_afl.sh (auto-detected) or pass via:
#   TS_GRAMMAR=$(realpath tree-sitter-solidity/libtree-sitter-solidity.so)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GRAMMAR_DIR="$REPO_ROOT/tree-sitter-solidity"

if [[ ! -f "$GRAMMAR_DIR/Makefile" ]]; then
    echo "ERROR: $GRAMMAR_DIR/Makefile not found — initialize the submodule:" >&2
    echo "  git submodule update --init tree-sitter-solidity" >&2
    exit 1
fi

make -C "$GRAMMAR_DIR" -j$(nproc) libtree-sitter-solidity.so

echo "Built: $GRAMMAR_DIR/libtree-sitter-solidity.so"
