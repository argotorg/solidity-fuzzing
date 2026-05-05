#!/usr/bin/env bash
# Build the host tree under build/ that the AFL pipeline depends on:
# the (uninstrumented) sol_afl_diff_runner used for crash replay, plus
# the three external projects driven by cmake (AFLplusplus producing
# afl-clang-fast, afl-ts producing libts.so, tree-sitter-solidity
# producing libtree-sitter-solidity.so).
#
# After this script, run tools/afl/build_instrumented.sh to produce the
# AFL-instrumented harness in build_afl/.
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"

mkdir -p "$BUILD_DIR"

cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

cmake --build "$BUILD_DIR" -j"$(nproc)" \
    --target sol_afl_diff_runner aflplusplus afl_ts tree_sitter_solidity
