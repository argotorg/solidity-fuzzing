#!/usr/bin/env bash
# Launch a protobuf fuzzer under afl-fuzz with the matching LPM custom mutator.
#
#   scripts/run_ossfuzz_afl.sh <fuzzer> <corpus_dir> [findings_dir]
#
# <fuzzer> is the binary name under build_afl/tools/ossfuzz/, e.g.
# sol_proto_ossfuzz_evmone. The corpus dir must hold at least one non-empty
# seed. Extra afl-fuzz flags can be appended after a trailing --.
set -eu

ROOTDIR="$(realpath "$(dirname "$0")/..")"
FUZZER="${1:?usage: run_ossfuzz_afl.sh <fuzzer> <corpus_dir> [findings_dir]}"
CORPUS="${2:?need a corpus dir}"
FINDINGS="${3:-findings_${FUZZER}}"

# Map fuzzer -> grammar -> mutator .so.
case "$FUZZER" in
  sol_proto_ossfuzz_evmone*|sol_ice_ossfuzz) base=sol2Proto ;;
  yul_proto_ossfuzz_evmone*)                 base=yulProto ;;
  sol_proto_ossfuzz_nondiff)                 base=solProto ;;
  shuffler_proto_ossfuzz)                    base=shufflerProto ;;
  sol_recstruct_alias_ossfuzz)               base=solRecStructAliasProto ;;
  sol_roundtrip_ossfuzz)                     base=solRoundtripProto ;;
  abiv2_proto_ossfuzz)                       base=abiV2Proto ;;
  *) echo "unknown fuzzer: $FUZZER" >&2; exit 1 ;;
esac

export AFL_CUSTOM_MUTATOR_LIBRARY="${ROOTDIR}/deps_afl/lib/lib${base}_lpm_mutator.so"
export AFL_CUSTOM_MUTATOR_ONLY=1   # only the LPM grammar mutator, no byte havoc
export AFL_SKIP_CPUFREQ=1

exec "${ROOTDIR}/AFLplusplus/afl-fuzz" -i "$CORPUS" -o "$FINDINGS" -m none -t 2000 \
  -- "${ROOTDIR}/build_afl/tools/ossfuzz/${FUZZER}"
