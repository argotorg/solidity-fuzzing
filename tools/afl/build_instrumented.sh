#!/usr/bin/env bash
# Build sol_afl_diff_runner (and the libsolc / evmone / supporting libs it
# links against) with afl-clang-fast so AFL++ gets edge-coverage feedback.
#
# Output tree: build_afl/  — separate from build/ (host gcc) and
# build_ossfuzz/ (Docker libFuzzer) so the three toolchains never clobber
# each other's object files. Same source tree, three build trees.
#
# Re-run after toolchain or source changes; cmake handles incremental
# rebuilds. ccache is enabled via the same launcher pattern as build/.
#
# Optional opt-ins (export before running):
#   AFL_HARDEN=1           -fstack-protector-all + extra hardening
#   AFL_USE_ASAN=1         AddressSanitizer  (~2x slowdown, catches more)
#   AFL_USE_UBSAN=1        UndefinedBehaviorSanitizer
#   AFL_USE_MSAN=1         MemorySanitizer (requires libc++ rebuild — skip
#                          unless you know what you're doing)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build_afl"

AFL_CC="$REPO_ROOT/AFLplusplus/afl-clang-fast"
AFL_CXX="$REPO_ROOT/AFLplusplus/afl-clang-fast++"

if [[ ! -x "$AFL_CC" || ! -x "$AFL_CXX" ]]; then
    echo "ERROR: vendored AFL++ not built — $AFL_CC missing." >&2
    echo "  Build it first: cmake --build $REPO_ROOT/build --target aflplusplus" >&2
    echo "  (it's part of the default \`make\` target if you've configured build/)" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

# afl-clang-fast{,++} are wrappers around clang that add the instrumentation
# pass. Pass them as CMAKE_{C,CXX}_COMPILER so the whole tree — including
# the evmone ExternalProject — picks them up.
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$AFL_CC" \
    -DCMAKE_CXX_COMPILER="$AFL_CXX" \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    `# Workaround for cmake 3.27+ × AFL++: cmake passes` \
    `# -Wl,--dependency-file=... at link time; afl-clang-fast++ wrapper` \
    `# doesn't unwrap it cleanly and clang errors with "unknown argument".` \
    -DCMAKE_C_LINKER_DEPFILE_SUPPORTED=FALSE \
    -DCMAKE_CXX_LINKER_DEPFILE_SUPPORTED=FALSE

# Note: CMakeLists.txt detects afl-clang-fast as our compiler and forces
# the evmone external project to use stock clang instead — works around a
# separate afl-clang-fast wrapper bug that mangles -Wl,-soname when linking
# shared libraries. Trade-off: evmone gets no AFL instrumentation. Most
# bugs we hunt live in solc, which IS instrumented. Revisit when AFL++
# fixes its clang wrapper.

cmake --build "$BUILD_DIR" -j$(nproc) --target sol_afl_diff_runner

echo
echo "Built: $BUILD_DIR/tools/afl/sol_afl_diff_runner"
echo "Run with: tools/afl/run_afl.sh"
