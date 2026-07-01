#!/usr/bin/env bash
# Build the protobuf fuzzers under AFL++ — afl-clang-fast++ + the system
# libstdc++. No libc++, no Docker.
#
# Only libprotobuf-mutator is built from source (into deps_afl/, against the
# system protobuf); boost / protobuf / abseil come from the system and evmone
# is built in-tree by the afl build. The fuzzers go into build_afl/ alongside
# sol_afl_diff_runner — one AFL tree for everything.
#
# Requirements (Arch package names in parentheses):
#   AFL++ built       (run tools/afl/build_afl.sh first)
#   clang/clang++     (clang)            — builds LPM + the mutator .so's
#   protobuf + abseil (protobuf)         — system, libstdc++
#   boost (static)    (boost)            — system, libstdc++
#   cmake, ninja, make, git, protoc, ccache
set -ex

ROOTDIR="$(realpath "$(dirname "$0")/..")"
DEPS="${ROOTDIR}/deps_afl"
BUILDDIR="${ROOTDIR}/build_afl"
AFLCC="${ROOTDIR}/AFLplusplus/afl-clang-fast"
AFLCXX="${ROOTDIR}/AFLplusplus/afl-clang-fast++"
ENGINE="${ROOTDIR}/AFLplusplus/utils/aflpp_driver/libAFLDriver.a"

if [[ ! -x "${AFLCXX}" || ! -f "${ENGINE}" ]]; then
  echo "AFL++ not built. Run: tools/afl/build_afl.sh" >&2
  exit 1
fi

# Each proto grammar: <basename> <fully-qualified top message type>. The
# harnesses share these grammars; one mutator .so is built per grammar.
GRAMMARS=(
  "sol2Proto solidity::test::sol2protofuzzer::Program"
  "yulProto solidity::yul::test::yul_fuzzer::Program"
  "solProto solidity::test::solprotofuzzer::Program"
  "shufflerProto solidity::yul::test::shuffler_fuzzer::ShuffleInput"
  "solRecStructAliasProto solidity::test::solrecstructalias::Program"
  "solRoundtripProto solidity::test::solroundtrip::Program"
  "abiV2Proto solidity::test::abiv2fuzzer::Contract"
)

# libprotobuf-mutator, built static + PIC against the system protobuf.
build_lpm() {
  if [[ -f "${DEPS}/lib/libprotobuf-mutator.a" ]]; then return; fi
  local src="${DEPS}/src/libprotobuf-mutator"
  local build="${DEPS}/build/libprotobuf-mutator"
  if [[ ! -d "${src}/.git" ]]; then
    git clone --depth 1 https://github.com/google/libprotobuf-mutator.git "${src}"
  fi
  cmake -S "${src}" -B "${build}" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_STANDARD=20 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=OFF \
    -DLIB_PROTO_MUTATOR_TESTING=OFF -DLIB_PROTO_MUTATOR_EXAMPLES=OFF \
    -DCMAKE_INSTALL_PREFIX="${DEPS}"
  cmake --build "${build}" -j"$(nproc)"
  cmake --install "${build}"
}

# Regenerate the *.pb.{cc,h} with the system protoc so they match the linked
# system libprotobuf (git-ignored, regenerated every build).
generate_bindings() {
  cd "${ROOTDIR}/tools/ossfuzz"
  local g base
  for g in "${GRAMMARS[@]}"; do
    base="${g%% *}"
    protoc "${base}.proto" --cpp_out .
  done
}

# One AFL++ custom-mutator .so per grammar: lpm_afl_mutator.cc + the grammar's
# bindings, linked against LPM + the system protobuf. Plain clang++ — the .so is
# loaded by afl-fuzz itself, so it must not carry AFL instrumentation.
build_mutators() {
  cd "${ROOTDIR}"
  local g base type
  for g in "${GRAMMARS[@]}"; do
    base="${g%% *}"; type="${g#* }"
    clang++ -O2 -fPIC -shared -std=gnu++20 -g \
      -I "${DEPS}/include/libprotobuf-mutator" -I tools/ossfuzz \
      $(pkg-config --cflags protobuf) \
      -DLPM_PROTO_HEADER="\"${base}.pb.h\"" -DLPM_PROTO_TYPE="${type}" \
      tools/ossfuzz/lpm_afl_mutator.cc "tools/ossfuzz/${base}.pb.cc" \
      "${DEPS}/lib/libprotobuf-mutator.a" $(pkg-config --libs protobuf) \
      -o "${DEPS}/lib/lib${base}_lpm_mutator.so"
  done
}

# Configure + build the proto fuzzers in build_afl/ with the AFL toolchain. The
# top-level CMakeLists detects afl-clang-fast and builds evmone static, and the
# OSSFUZZ path links the AFL++ driver via LIB_FUZZING_ENGINE.
build_fuzzers() {
  cmake -S "${ROOTDIR}" -B "${BUILDDIR}" \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}" \
    -DCMAKE_C_COMPILER="${AFLCC}" -DCMAKE_CXX_COMPILER="${AFLCXX}" \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
    -DCMAKE_C_LINKER_DEPFILE_SUPPORTED=FALSE \
    -DCMAKE_CXX_LINKER_DEPFILE_SUPPORTED=FALSE \
    -DOSSFUZZ=ON -DLPM_PREFIX="${DEPS}" -DLIB_FUZZING_ENGINE="${ENGINE}"
  # Build the evmone static archive first. The yul_proto_* harnesses link
  # libevmone-standalone.a as a plain file path, and the evmone_external
  # ExternalProject byproduct has no make rule when the linking targets are
  # built in isolation (add_dependencies only orders it when it's already in
  # the build set). Building it explicitly here creates the archive so the
  # subsequent harness link finds it, instead of failing with
  # "No rule to make target '.../libevmone-standalone.a'".
  cmake --build "${BUILDDIR}" -j"$(nproc)" --target evmone_external
  cmake --build "${BUILDDIR}" -j"$(nproc)" --target ossfuzz_proto ossfuzz_abiv2
}

build_lpm
generate_bindings
build_mutators
build_fuzzers
