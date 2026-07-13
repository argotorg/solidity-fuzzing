#!/usr/bin/env bash
# Launch a protobuf fuzzer under afl-fuzz with an AddressSanitizer-instrumented
# LPM custom mutator, so heap corruption *inside the fuzzer itself* is trapped at
# the faulting write with a full stack — instead of surfacing as a bare glibc
# "malloc(): invalid next size" abort that kills the worker with no diagnostics.
#
# Why this exists
# ---------------
# The LPM grammar mutator runs in-process inside afl-fuzz (AFL_CUSTOM_MUTATOR_ONLY
# =1). If it — or the protobuf runtime it calls — corrupts the heap, the whole
# afl-fuzz *parent* dies; the target child then aborts in its forkserver with
# "read from AFL++ tool" (afl-compiler-rt.o.c:1241) simply because its controller
# vanished. A stock build only shows glibc's post-hoc abort. This script instead:
#
#   1. builds libprotobuf-mutator with -fsanitize=address (isolated under
#      deps_afl/asan/, so the production deps_afl/ .so's are untouched);
#   2. builds the grammar's mutator .so with ASan + -shared-libasan;
#   3. launches the *stock* target binary from build_afl/ under afl-fuzz with the
#      shared ASan runtime LD_PRELOAD'ed into the parent.
#
# Only the mutator .so needs ASan *compilation* (its loads/stores get checked, so
# the out-of-bounds access aborts with file:line + stack). afl-fuzz needs no
# rebuild — LD_PRELOAD makes ASan's malloc interposer cover the whole parent
# process. The target binary in build_afl/ is reused as-is; it is the bystander,
# not the culprit. When a worker corrupts, ASan writes the report to
# <findings>/asan.<pid> and aborts.
#
# Usage
# -----
#   tools/ossfuzz/run_ossfuzz_afl_asan.sh <fuzzer> <corpus_dir> [findings_dir]
#   tools/ossfuzz/run_ossfuzz_afl_asan.sh --resume <fuzzer> [findings_dir]
#
# <fuzzer> is the binary name under build_afl/tools/ossfuzz/, e.g.
# yul_proto_ossfuzz_evmone_ssacfg. Default findings_dir is findings_asan_<fuzzer>.
#
# Env:
#   JOBS=<n>   fan out over n cores (1 master + n-1 secondaries, one per tmux
#              window in session "aflasan_<fuzzer>"). Default 1 (foreground).
#   CLANG / CLANGXX   override the compiler used to build the ASan bits.
#
# Prereqs: run tools/ossfuzz/build_ossfuzz.sh first (for the target binary under
# build_afl/), plus clang with the shared ASan runtime (libclang_rt.asan*.so).
set -eu

ROOTDIR="$(realpath "$(dirname "$0")/../..")"
DEPS="${ROOTDIR}/deps_afl"
ASANDIR="${DEPS}/asan"                       # all ASan artifacts (gitignored via /deps_afl/)
LPM_PREFIX="${ASANDIR}/lpm"                  # ASan libprotobuf-mutator install prefix
MUT_DIR="${ASANDIR}/lib"                     # ASan mutator .so's live here

CLANG="${CLANG:-clang}"
CLANGXX="${CLANGXX:-clang++}"

# --- arg parsing (mirrors run_ossfuzz_afl.sh) -------------------------------
RESUME=0
if [ "${1:-}" = "--resume" ]; then RESUME=1; shift; fi
USAGE="usage: run_ossfuzz_afl_asan.sh [--resume] <fuzzer> <corpus_dir> [findings_dir]"
FUZZER="${1:?$USAGE}"
if [ "$RESUME" -eq 1 ]; then
  INPUT="-"
  FINDINGS="${2:-findings_asan_${FUZZER}}"
else
  INPUT="${2:?need a corpus dir}"
  FINDINGS="${3:-findings_asan_${FUZZER}}"
fi

# --- fuzzer -> grammar base, and base -> fully-qualified message type --------
# (bases + types kept in sync with tools/ossfuzz/build_ossfuzz.sh)
case "$FUZZER" in
  sol_proto_ossfuzz_evmone*|sol_ice_ossfuzz*) BASE=sol2Proto ;;
  yul_proto_ossfuzz_evmone*)                 BASE=yulProto ;;
  sol_proto_ossfuzz_nondiff)                 BASE=solProto ;;
  shuffler_proto_ossfuzz)                    BASE=shufflerProto ;;
  sol_recstruct_alias_ossfuzz)               BASE=solRecStructAliasProto ;;
  sol_roundtrip_ossfuzz)                     BASE=solRoundtripProto ;;
  abiv2_proto_ossfuzz)                       BASE=abiV2Proto ;;
  *) echo "unknown fuzzer: $FUZZER" >&2; exit 1 ;;
esac
case "$BASE" in
  sol2Proto)              TYPE="solidity::test::sol2protofuzzer::Program" ;;
  yulProto)               TYPE="solidity::yul::test::yul_fuzzer::Program" ;;
  solProto)               TYPE="solidity::test::solprotofuzzer::Program" ;;
  shufflerProto)          TYPE="solidity::yul::test::shuffler_fuzzer::ShuffleInput" ;;
  solRecStructAliasProto) TYPE="solidity::test::solrecstructalias::Program" ;;
  solRoundtripProto)      TYPE="solidity::test::solroundtrip::Program" ;;
  abiV2Proto)             TYPE="solidity::test::abiv2fuzzer::Contract" ;;
esac

BIN="${ROOTDIR}/build_afl/tools/ossfuzz/${FUZZER}"
[ -x "$BIN" ] || { echo "target not built: $BIN (run tools/ossfuzz/build_ossfuzz.sh)" >&2; exit 1; }

# --- locate the shared ASan runtime for LD_PRELOAD --------------------------
ASAN_RT=""
for n in libclang_rt.asan-x86_64.so libclang_rt.asan.so; do
  p="$("$CLANG" -print-file-name="$n" 2>/dev/null || true)"
  if [ -f "$p" ]; then ASAN_RT="$p"; break; fi
done
[ -n "$ASAN_RT" ] || { echo "ERROR: shared ASan runtime not found (libclang_rt.asan*.so); is compiler-rt installed?" >&2; exit 1; }

# --- 1. ASan libprotobuf-mutator (cached) -----------------------------------
build_lpm_asan() {
  [ -f "${LPM_PREFIX}/lib/libprotobuf-mutator.a" ] && return
  echo ">>> building ASan libprotobuf-mutator into ${LPM_PREFIX}" >&2
  local src="${DEPS}/src/libprotobuf-mutator"
  if [ ! -d "${src}/.git" ]; then
    git clone --depth 1 https://github.com/google/libprotobuf-mutator.git "${src}"
  fi
  cmake -S "${src}" -B "${ASANDIR}/lpm-build" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_STANDARD=20 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_C_COMPILER="${CLANG}" -DCMAKE_CXX_COMPILER="${CLANGXX}" \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=OFF \
    -DLIB_PROTO_MUTATOR_TESTING=OFF -DLIB_PROTO_MUTATOR_EXAMPLES=OFF \
    -DCMAKE_INSTALL_PREFIX="${LPM_PREFIX}"
  cmake --build "${ASANDIR}/lpm-build" -j"$(nproc)"
  cmake --install "${ASANDIR}/lpm-build"
}

# --- 2. ASan mutator .so (always rebuilt: fast, picks up source edits) -------
build_mutator_asan() {
  echo ">>> building ASan mutator ${BASE} -> ${MUT_DIR}/lib${BASE}_lpm_mutator.so" >&2
  mkdir -p "${MUT_DIR}"
  # Regenerate bindings with the system protoc so they match the linked system
  # libprotobuf (git-ignored, same as build_ossfuzz.sh).
  ( cd "${ROOTDIR}/tools/ossfuzz" && protoc "${BASE}.proto" --cpp_out . )
  # -shared-libasan so the .so references the shared runtime; the LD_PRELOAD at
  # launch is what actually initialises ASan early in the afl-fuzz parent.
  "${CLANGXX}" -O1 -g -fPIC -shared -std=gnu++20 \
    -fsanitize=address -shared-libasan -fno-omit-frame-pointer \
    -I "${LPM_PREFIX}/include/libprotobuf-mutator" -I "${ROOTDIR}/tools/ossfuzz" \
    $(pkg-config --cflags protobuf) \
    -DLPM_PROTO_HEADER="\"${BASE}.pb.h\"" -DLPM_PROTO_TYPE="${TYPE}" \
    "${ROOTDIR}/tools/ossfuzz/lpm_afl_mutator.cc" "${ROOTDIR}/tools/ossfuzz/${BASE}.pb.cc" \
    "${LPM_PREFIX}/lib/libprotobuf-mutator.a" $(pkg-config --libs protobuf) \
    -o "${MUT_DIR}/lib${BASE}_lpm_mutator.so"
}

build_lpm_asan
build_mutator_asan
MUTATOR="${MUT_DIR}/lib${BASE}_lpm_mutator.so"

# --- 3. seed an empty corpus dir (non-resume), like run_ossfuzz_afl.sh -------
if [ "$RESUME" -eq 0 ]; then
  if [ ! -d "$INPUT" ] || [ -z "$(find "$INPUT" -maxdepth 1 -type f ! -empty -print -quit)" ]; then
    echo "seeding empty corpus dir: $INPUT" >&2
    mkdir -p "$INPUT"
    printf '# empty seed: valid text-format protobuf, parses to a default message\n' > "$INPUT/seed"
  fi
fi

mkdir -p "$FINDINGS"
FINDINGS_ABS="$(realpath "$FINDINGS")"

# --- fuzzer + ASan environment ----------------------------------------------
# detect_container_overflow=0: mixing our ASan .so with the *non*-ASan system
#   libprotobuf.so trips a benign container-overflow false positive on protobuf's
#   RepeatedField/string annotations — not the heap corruption we're hunting.
# abort_on_error=1: abort (not exit) on the first real finding.
# symbolize=0: REQUIRED by afl-fuzz (check_asan_opts aborts otherwise). The
#   report is therefore raw "module+offset"; symbolize it after the fact with
#   tools/ossfuzz/symbolize_asan.sh (the .so is built with -g).
# log_path: write the report to a file so afl-fuzz's TUI can't scroll it away.
ASAN_OPTS="detect_container_overflow=0:detect_leaks=0:abort_on_error=1:symbolize=0:print_stats=0:log_path=${FINDINGS_ABS}/asan"

export AFL_CUSTOM_MUTATOR_LIBRARY="${MUTATOR}"
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
# afl-fuzz refuses to run with LD_PRELOAD/ASan unless told the target is ASan-aware.
export AFL_USE_ASAN=1
export AFL_PRELOAD="${ASAN_RT}"          # ASan into the target children too (harmless)
export LD_PRELOAD="${ASAN_RT}"           # ASan into the afl-fuzz parent (the point)
export ASAN_OPTIONS="${ASAN_OPTS}"

AFL="${ROOTDIR}/AFLplusplus/afl-fuzz"

echo ">>> mutator : ${MUTATOR}" >&2
echo ">>> asan_rt : ${ASAN_RT}" >&2
echo ">>> reports : ${FINDINGS_ABS}/asan.<pid>   (also error.txt on parent death)" >&2
echo ">>> symbolize a report with: tools/ossfuzz/symbolize_asan.sh ${FINDINGS_ABS}/asan.<pid>" >&2

JOBS="${JOBS:-1}"
if [ "$JOBS" -le 1 ]; then
  exec "$AFL" -i "$INPUT" -o "$FINDINGS" -m none -t 2000 -- "$BIN"
fi

# --- parallel: 1 master + (JOBS-1) secondaries in tmux ----------------------
command -v tmux >/dev/null || { echo "JOBS>1 needs tmux" >&2; exit 1; }
ENVX="AFL_CUSTOM_MUTATOR_LIBRARY='${MUTATOR}' AFL_CUSTOM_MUTATOR_ONLY=1"
ENVX="$ENVX AFL_SKIP_CPUFREQ=1 AFL_DISABLE_TRIM=1 AFL_USE_ASAN=1"
ENVX="$ENVX AFL_PRELOAD='${ASAN_RT}' LD_PRELOAD='${ASAN_RT}' ASAN_OPTIONS='${ASAN_OPTS}'"
SESSION="aflasan_${FUZZER}"

tmux new-session -d -s "$SESSION" -n m00 \
  "env $ENVX '$AFL' -i '$INPUT' -o '$FINDINGS' -M m00 -m none -t 2000 -- '$BIN'; exec ${SHELL:-/bin/sh}"
for i in $(seq 1 $((JOBS - 1))); do
  id=$(printf 's%02d' "$i")
  tmux new-window -t "$SESSION" -n "$id" \
    "env $ENVX '$AFL' -i '$INPUT' -o '$FINDINGS' -S '$id' -m none -t 2000 -- '$BIN'; exec ${SHELL:-/bin/sh}"
done
tmux select-window -t "$SESSION:m00"
echo "launched $JOBS ASan afl-fuzz instances in tmux session '$SESSION'"
echo "attach:  tmux attach -t $SESSION"
echo "reports: ls ${FINDINGS_ABS}/asan.*   (grep -l 'AddressSanitizer' ${FINDINGS_ABS}/asan.*)"
echo "stop:    tmux kill-session -t $SESSION"
