# Protobuf fuzzers (AFL++ + libprotobuf-mutator)

LPM harnesses for solc and Yul. Each uses `DEFINE_PROTO_FUZZER`: a
protobuf grammar is converted to Solidity/Yul, compiled, deployed on
evmone, and checked. They run under AFL++ — the harness stays
engine-agnostic (libFuzzer-style `LLVMFuzzerTestOneInput`), and AFL drives
LPM through a per-grammar custom mutator (below).

## Build & run

```bash
tools/ossfuzz/build_ossfuzz.sh                                   # -> build_afl/
tools/ossfuzz/run_ossfuzz_afl.sh sol_proto_ossfuzz_evmone seeds_sol_proto
```

`run_ossfuzz_afl.sh` picks the matching mutator and sets
`AFL_CUSTOM_MUTATOR_ONLY=1`, so only the grammar mutator runs (no byte
havoc on the serialized protobuf). The seed dir needs one non-empty file
in the harness's text-format protobuf — a one-byte seed (empty default
message) is enough; the mutator grows structure from there. Solidity
*source* files (e.g. `corpus_afl/`) are NOT valid seeds for proto fuzzers.

Resume a stopped run from its own findings dir (no corpus dir needed):

```bash
tools/ossfuzz/run_ossfuzz_afl.sh --resume sol_proto_ossfuzz_evmone
```

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
- `sol_proto_ossfuzz_nondiff` — legacy non-differential (older solProto grammar)
- `yul_proto_ossfuzz_evmone[_ssacfg,_no_ssa,_check_stack_alloc]` — Yul
- `yul_proto_ossfuzz_evmone_single_pass_<c S L M s r D>` — one pass

Non-differential / crash-only:

- `sol_ice_ossfuzz` — frontend ICE hunter (see below)
- `sol_ice_ossfuzz_ssacfg` — same, driving the experimental SSA-CFG backend
- `sol_recstruct_alias_ossfuzz` — recursive-struct alias copy (#1392)
- `sol_roundtrip_ossfuzz` — primitive identity oracles
- `shuffler_proto_ossfuzz` — SSA stack shuffler
- `abiv2_proto_ossfuzz` — ABIv2 coder

## `sol_ice_ossfuzz` — frontend ICE hunter

Compile-only, non-differential: converts a `sol2Proto` program to Solidity and
calls `CompilerStack::compile()` once (no evmone), so it iterates far faster
than the differential fuzzers. It hunts *internal* compiler errors — it lets
`InternalCompilerError`, `solAssert`, and boost assertions escape as crashes
and swallows only known non-bugs (`UnimplementedFeatureError`, stack-too-deep),
matching `test/tools/fuzzer_common.cpp`. The other `sol_proto_*` fuzzers should
ignore ICE and leave it to this one. viaIR/optimizer come from the proto, so
one binary covers legacy + IR + opt/unopt; sources over 8 KB are skipped.

```bash
tools/ossfuzz/run_ossfuzz_afl.sh sol_ice_ossfuzz seeds_sol_ice
```

`sol_ice_ossfuzz_ssacfg` is the same harness with the experimental SSA-CFG
backend baked in (`-DFUZZER_MODE_SSACFG`, same pattern as the `_viair` variant),
forcing `setExperimental(true)` + `setViaIR(true)` + `setViaSSACFG(true)` — the
CLI's `--experimental --via-ssa-cfg`. `build_ossfuzz.sh` builds both. Reproduce
via solc, not the (differential) debug runners:

```bash
PROTO_FUZZER_DUMP_PATH=bad.sol build_afl/tools/ossfuzz/sol_ice_ossfuzz_ssacfg crash-file
build/solidity/solc/solc --experimental --via-ssa-cfg bad.sol
```

## Reproduce

Crash inputs are raw protobuf. Point the *fuzzer* at the crash file with a
dump env var to write out the human-readable source, then replay that with
the matching debug runner. Fuzzers live in `build_afl/`, runners in
`build/` — you need both build trees (see the top-level CLAUDE.md).

**Solidity** (`sol_proto_ossfuzz_evmone`, `sol_ice_ossfuzz`,
`sol_recstruct_alias_ossfuzz`, `sol_roundtrip_ossfuzz`, …):

```bash
PROTO_FUZZER_DUMP_PATH=bad.sol \
  build_afl/tools/ossfuzz/sol_proto_ossfuzz_evmone crash-file
build/tools/runners/sol_debug_runner bad.sol
```

**Yul** (`yul_proto_ossfuzz_evmone*`) — the optimizer step sequence is part
of the input, so also dump it (`PROTO_FUZZER_DUMP_SEQ_PATH`) and feed it
back. Without the sequences the runner uses solc defaults and may not
reproduce:

```bash
PROTO_FUZZER_DUMP_PATH=bad.yul PROTO_FUZZER_DUMP_SEQ_PATH=bad.seq \
  build_afl/tools/ossfuzz/yul_proto_ossfuzz_evmone crash-file
build/tools/runners/yul_debug_runner bad.yul \
  --optimizer-sequence "<steps>" \
  --optimizer-cleanup-sequence "<steps>"
```

Pass `--optimizer-sequence ""` for an explicitly empty sequence; omit the
flag entirely to fall back to the solc default.

Both runners exit **0** match, **1** differential mismatch, **2** compile
fail, **3** ICE. They run every config and print per-config bytecode, logs,
and storage. Common flags:

- `-v`/`--verbose` — full logs + storage for all configs (not just counts)
- `-q`/`--quiet` — one-line summary only (used by delta debuggers)
- `--output-dir DIR` — write `.bytecode.hex` + `.log` per config
- `--calldata HEX` — extra calldata appended after the selector
- `sol` only: `--via-ir true|false`, `--afl` (replay `sol_afl_diff_runner`
  inputs), `--timeout N` (external `timeout N solc …` for hang triage)

`shuffler_proto_ossfuzz` instead dumps a `.stack` file — replay with
`stackshuffler` (see ../shuffler-fuzzer).

## Corpus check

```bash
tools/runners/check_diversity_and_errors.sh corpus_dir 300 \
  build_afl/tools/ossfuzz/sol_proto_ossfuzz_evmone
```

Dumps N entries, compiles each with solc, tallies language features.
