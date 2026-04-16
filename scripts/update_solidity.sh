#!/usr/bin/env bash
# Point the solidity submodule at a ref (branch, tag, commit, or PR number)
# and rebuild both the normal build and the fuzz build.
#
# Usage:
#   scripts/update_solidity.sh <ref>
#   scripts/update_solidity.sh pr/16607        # PR head
#   scripts/update_solidity.sh branch/develop  # latest tip of origin/develop
#   scripts/update_solidity.sh v0.8.33         # tag
#   scripts/update_solidity.sh 449363e72       # commit
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <ref|pr/NUMBER|branch/NAME>" >&2
  exit 1
fi

REF="$1"
ROOTDIR="$(realpath "$(dirname "$0")/..")"
cd "${ROOTDIR}/solidity"

# Refresh all remote branches and tags so branch/tag/commit refs resolve to
# their latest origin state.
git fetch --tags --prune origin

if [[ "$REF" =~ ^pr/([0-9]+)$ ]]; then
  PR="${BASH_REMATCH[1]}"
  git fetch origin "pull/${PR}/head:pr-${PR}"
  git checkout "pr-${PR}"
elif [[ "$REF" =~ ^branch/(.+)$ ]]; then
  BRANCH="${BASH_REMATCH[1]}"
  # Checking out a remote-tracking ref detaches HEAD at the freshly-fetched
  # remote tip — no local tracking branch gets updated, which is what we want
  # for a throwaway fuzzing checkout.
  git checkout "origin/${BRANCH}"
else
  git checkout "$REF"
fi

git submodule update --init --recursive
cd "${ROOTDIR}"

rm -rf build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer" -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" ..
make -j"$(nproc)"
cd "${ROOTDIR}"

docker run --rm -v "${ROOTDIR}":/src/solidity-fuzzing solidity-ossfuzz \
  /src/solidity-fuzzing/scripts/build_ossfuzz.sh
