# Protobuf fuzzers (AFL++ + libprotobuf-mutator)

LPM harnesses for solc and Yul. Each uses `DEFINE_PROTO_FUZZER`: a
protobuf grammar is converted to Solidity/Yul, compiled, deployed on
evmone, and checked. They run under AFL++ — the harness stays
engine-agnostic (libFuzzer-style `LLVMFuzzerTestOneInput`), and AFL drives
LPM through a per-grammar custom mutator (below).

## Build & run

```bash
scripts/build_ossfuzz.sh                                   # -> build_afl/
scripts/run_ossfuzz_afl.sh sol_proto_ossfuzz_evmone corpus_sol
```

`run_ossfuzz_afl.sh` picks the matching mutator and sets
`AFL_CUSTOM_MUTATOR_ONLY=1`, so only the grammar mutator runs (no byte
havoc on the serialized protobuf). The corpus needs one non-empty seed.

## LPM ↔ AFL mutator

`lpm_afl_mutator.cc` is the bridge: `afl_custom_fuzz` deserializes the
(text-format) protobuf the harness expects, runs
`protobuf_mutator::Mutator` over the message tree, and re-serializes — so
every input stays a valid program and the existing corpus is reused. One
`.so` per grammar is built into `deps_afl/lib/` (the proto type is a
compile-time `-D`). The engine is AFL++'s `libAFLDriver.a`
(`LIB_FUZZING_ENGINE`), replacing libFuzzer.

## Fuzzers

Differential — unopt vs opt, deployed on evmone, comparing status /
output / logs / storage:

- `sol_proto_ossfuzz_evmone` — Solidity, same viaIR on both sides
- `sol_proto_ossfuzz_evmone_viair` — legacy vs IR
- `yul_proto_ossfuzz_evmone[_ssacfg,_no_ssa,_check_stack_alloc]` — Yul
- `yul_proto_ossfuzz_evmone_single_pass_<c S L M s r D>` — one pass

Non-differential / crash-only:

- `sol_ice_ossfuzz` — frontend ICE hunter
- `sol_recstruct_alias_ossfuzz` — recursive-struct alias copy (#1392)
- `sol_roundtrip_ossfuzz` — primitive identity oracles
- `shuffler_proto_ossfuzz` — SSA stack shuffler
- `abiv2_proto_ossfuzz` — ABIv2 coder

## Reproduce

Dump the source, then replay with the debug runner (both in `build/`):

```bash
PROTO_FUZZER_DUMP_PATH=bad.sol \
  build_afl/tools/ossfuzz/sol_proto_ossfuzz_evmone crash-file
build/tools/runners/sol_debug_runner bad.sol
# yul: dump bad.yul the same way, then yul_debug_runner bad.yul
```

Exit codes: 0 match, 1 differential mismatch, 2 compile fail, 3 ICE. The
debug runners run all configs and print per-config bytecode, logs, and
storage; `--output-dir` writes them. `shuffler_proto_ossfuzz` dumps a
`.stack` file — replay with `stackshuffler` (see ../shuffler-fuzzer).

## Corpus check

```bash
tools/runners/check_diversity_and_errors.sh corpus_dir 300 \
  build_afl/tools/ossfuzz/sol_proto_ossfuzz_evmone
```

Dumps N entries, compiles each with solc, tallies language features.
