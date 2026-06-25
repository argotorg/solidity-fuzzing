#!/usr/bin/env bash
# Build the libFuzzer OSS-Fuzz harnesses natively (no Docker).
#
# The local fuzz build only enables -fsanitize=fuzzer + UBSan (no MSan), so —
# unlike Google's OSS-Fuzz infra — it does not need a libc++-instrumented world.
# We link against the system's libstdc++-built boost, protobuf 35 and abseil,
# and build only the two deps that aren't packaged for this purpose
# (libprotobuf-mutator and evmone-standalone) into deps/.
#
# Requirements (Arch package names in parentheses):
#   clang/clang++         (clang)        — libFuzzer is clang-only
#   protoc                (protobuf)     — must match the linked libprotobuf
#   abseil headers/libs   (abseil-cpp)
#   static boost          (boost)        — /usr/lib/libboost_*.a
#   cmake, make, git
set -ex

ROOTDIR="$(realpath "$(dirname "$0")/..")"
BUILDDIR="${ROOTDIR}/build_ossfuzz"
DEPS="${ROOTDIR}/deps"
LPM_GIT="https://github.com/google/libprotobuf-mutator.git"

export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"

mkdir -p "${BUILDDIR}" "${DEPS}"

function generate_protobuf_bindings
{
  # Regenerated on every build with the *system* protoc so the bindings match
  # the libprotobuf we link against. Committed only so the LSP/IDE works.
  cd "${ROOTDIR}/tools/ossfuzz"
  for protoName in yul abiV2 sol sol2 shuffler solRecStructAlias solRoundtrip; do
    protoc "${protoName}"Proto.proto --cpp_out .
  done
}

# libprotobuf-mutator, built against the *system* protobuf (not its bundled
# copy) so there is no version skew with the protoc above. Installs
# libprotobuf-mutator{,-libfuzzer}.a + headers under deps/.
function build_libprotobuf_mutator
{
  if [[ -f "${DEPS}/lib/libprotobuf-mutator.a" ]]; then
    return
  fi
  local src="${DEPS}/src/libprotobuf-mutator"
  local build="${DEPS}/build/libprotobuf-mutator"
  if [[ ! -d "${src}/.git" ]]; then
    git clone --depth 1 "${LPM_GIT}" "${src}"
  fi
  cmake -S "${src}" -B "${build}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="${CC}" -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_CXX_STANDARD=20 \
    -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=OFF \
    -DLIB_PROTO_MUTATOR_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX="${DEPS}"
  cmake --build "${build}" -j"$(nproc)"
  cmake --install "${build}"
}

# evmone as a self-contained static archive (evmone-standalone.a). The harnesses
# call evmc_create_evmone() directly, so this is linked in — no libevmone.so at
# runtime. Instrumented like the harnesses (-fsanitize=fuzzer-no-link) so the
# fuzzer also gets coverage feedback from the EVM executor.
function build_evmone_standalone
{
  if [[ -f "${DEPS}/lib/libevmone-standalone.a" ]]; then
    return
  fi
  local build="${DEPS}/build/evmone"
  cmake -S "${ROOTDIR}/evmone" -B "${build}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="${CC}" -DCMAKE_CXX_COMPILER="${CXX}" \
    -DBUILD_SHARED_LIBS=OFF \
    -DEVMONE_TESTING=OFF -DBUILD_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX="${DEPS}" \
    -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link -fsanitize=undefined -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -D_GLIBCXX_ASSERTIONS"
  cmake --build "${build}" -j"$(nproc)"
  cmake --install "${build}"
}

function build_fuzzers
{
  cd "${BUILDDIR}"
  export CCACHE_DIR="${ROOTDIR}/.ccache"
  export CCACHE_BASEDIR="${ROOTDIR}"
  export CCACHE_NOHASHDIR=1
  mkdir -p "${CCACHE_DIR}"
  cmake "${ROOTDIR}" \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}" \
    -DCMAKE_TOOLCHAIN_FILE="${ROOTDIR}/cmake/toolchains/libfuzzer-native.cmake" \
    -DLPM_PREFIX="${DEPS}" -DEVMONE_PREFIX="${DEPS}" \
    -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
  ccache -z
  make ossfuzz ossfuzz_proto ossfuzz_abiv2 -j"$(nproc)"
  ccache -s
}

generate_protobuf_bindings
build_libprotobuf_mutator
build_evmone_standalone
build_fuzzers
