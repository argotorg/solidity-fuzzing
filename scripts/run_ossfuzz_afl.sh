#!/usr/bin/env bash
# Launch a protobuf fuzzer under afl-fuzz with the matching LPM custom mutator.
#
#   scripts/run_ossfuzz_afl.sh <fuzzer> <corpus_dir> [findings_dir]
#   scripts/run_ossfuzz_afl.sh --resume <fuzzer> [findings_dir]
#
# <fuzzer> is the binary name under build_afl/tools/ossfuzz/, e.g.
# sol_proto_ossfuzz_evmone. The corpus dir must hold at least one non-empty
# seed. With --resume, AFL re-reads its own findings dir (afl-fuzz -i-) and
# continues from the existing queue — no corpus dir needed.
set -eu

ROOTDIR="$(realpath "$(dirname "$0")/..")"

RESUME=0
if [ "${1:-}" = "--resume" ]; then RESUME=1; shift; fi

USAGE="usage: run_ossfuzz_afl.sh [--resume] <fuzzer> <corpus_dir> [findings_dir]"
FUZZER="${1:?$USAGE}"
if [ "$RESUME" -eq 1 ]; then
  INPUT="-"                          # AFL resume marker: re-read the findings dir
  FINDINGS="${2:-findings_${FUZZER}}"
else
  INPUT="${2:?need a corpus dir}"
  FINDINGS="${3:-findings_${FUZZER}}"
  # AFL aborts ("No usable test cases") on a missing or empty input dir, even
  # though the LPM custom mutator can grow a corpus from nothing. Drop in a
  # single seed so afl-fuzz has a queue entry to start mutating. The harness and
  # mutator use TEXT-format protobuf (DEFINE_PROTO_FUZZER's use_binary=false), so
  # the seed must be valid text format: a comment line is non-empty (AFL needs
  # that) yet parses to a default message — arbitrary bytes flood stderr with
  # "Error parsing text-format ... Program" instead.
  if [ ! -d "$INPUT" ] || [ -z "$(find "$INPUT" -maxdepth 1 -type f ! -empty -print -quit)" ]; then
    echo "seeding empty corpus dir: $INPUT" >&2
    mkdir -p "$INPUT"
    printf '# empty seed: valid text-format protobuf, parses to a default message\n' > "$INPUT/seed"
  fi
fi

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

exec "${ROOTDIR}/AFLplusplus/afl-fuzz" -i "$INPUT" -o "$FINDINGS" -m none -t 2000 \
  -- "${ROOTDIR}/build_afl/tools/ossfuzz/${FUZZER}"
