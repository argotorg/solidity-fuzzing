# Plan: Improve Solidity Proto-Fuzzer Diversity

Status: drafted 2026-04-27. Tier 0 to be implemented immediately; Tiers 1–3 staged.

## Problem statement

After a week of fuzzing with `sol_proto_ossfuzz_evmone` (and the related
`sol_proto_*` family driven by `tools/ossfuzz/sol2Proto.proto` +
`tools/ossfuzz/protoToSol2.cpp`), generated programs all look very similar.
Approximately 90% compile, but the corpus is structurally homogeneous: same
contract skeleton, same identifier shapes, narrow type variety, shallow
nesting. We are exercising too little of Solidity, even though libFuzzer has
had ample CPU time.

## Root cause #1 — hard caps in `protoToSol2.h`

```
s_maxContracts  = 2
s_maxFunctions  = 3   (per contract)
s_maxParams     = 2
s_maxExprDepth  = 2
s_maxStmtDepth  = 2
```

After a week, libFuzzer has exhausted the structural shapes reachable under
these caps. Identifier naming is also fully mechanical (`C0`, `f0_0`, `s0`,
`_var0`, `p0`, `p1`), so two programs differing only in literals look
identical to a human. Caps alone explain "everything looks the same" even
with 100% grammar coverage.

## Root cause #2 — entire subsystems missing from the proto

Proto-vs-spec coverage (cross-checked against
`solidity/docs/grammar/SolidityParser.g4` + `SolidityLexer.g4`) is roughly
**65% by feature count, ~40% by diversity impact**. The biggest holes are
not small details — they're whole language regions:

| Missing | Impact |
| --- | --- |
| **Inline assembly (Yul-in-Solidity)** | Solidity-to-Yul lowering paths never exercised; optimizer interactions across the boundary unreached. |
| **Multi-dim arrays, mappings-of-mappings** | `MappingType` is flat (`sol2Proto.proto:147–150`); state arrays are 1D only. Storage-layout codegen barely touched. |
| **Interfaces & abstract contracts** | `ContractKind` only has `CONTRACT` / `LIBRARY` (`sol2Proto.proto:1002–1006`). Abstract-method resolution untested. |
| **Constructor inheritance args** | `bases` is just indices, no `Base(args)` syntax. |
| **Function types as values** | Only simulated via pointers; native function-type ABI never tested. |
| **Low-level calls** (`.call{value:, gas:}`, delegatecall, staticcall) | Entirely absent. Whole call-options codegen path uncovered. |
| **`payable(...)` cast, struct literals `S({x:1})`, anonymous events, `type(C).creationCode/runtimeCode/interfaceId`** | Each a separate codegen path. |
| **Fixed-point** | Only the targeted ICE probe in `FixedAsmStmt`, no general fuzzing. |
| **Hex/unicode string literals, time units (seconds/minutes/days)** | All strings are `StringLiteral.seed`-derived. |
| **Locals are always `uint256`** (`VarDeclStmt`, `sol2Proto.proto:540–544`) | Eliminates type variety inside function bodies entirely. |

The proto has 24 statement variants, but with `s_maxStmtDepth=2` and
`s_maxExprDepth=2` they almost never compose into deep, varied programs.

## Could the `.g4` files drive generation?

Honestly: **as a checklist, yes; as a code generator, not realistically**.

- **Replace proto with grammar-directed fuzzer** (nautilus/grammarinator
  from `.g4`): biggest theoretical coverage, but a multi-month rewrite.
  nautilus is AGPL, which is a separate problem. We'd also lose the
  structured proto mutator that libFuzzer is good at.
- **Use `.g4` to mutate existing valid Solidity**: works, but most mutations
  break syntax; throughput collapses and we stop driving solc's deeper
  passes.
- **Use `.g4` as a spec checklist and extend the proto**: keeps existing
  infrastructure, lets us close gaps in priority order. Highest LOC-to-
  coverage ratio in the short term.

We'll go with the third. The `.g4` files become a TODO list, not a runtime
dependency.

## Plan, ordered by ROI

### Tier 0 — free wins (1 hour, do first to get a baseline)

- Bump caps in `tools/ossfuzz/protoToSol2.h`:
  - `s_maxContracts`  2 → 4
  - `s_maxFunctions`  3 → 6
  - `s_maxParams`     2 → 4
  - `s_maxExprDepth`  2 → 4
  - `s_maxStmtDepth`  2 → 4
- Randomize identifier suffixes from a name pool (helps human triage; small
  coverage gain from using identifiers as keccak/hash inputs and selector
  bytes).
- Measure edge-coverage delta over 24 h before doing anything else. This
  isolates how much of the same-y output is just caps.

### Tier 1 — high-leverage proto extensions (each ~1–2 days)

1. **Multi-dim arrays + nested mappings** (small grammar change, big
   storage-layout coverage gain).
2. **Constructor inheritance args** (`Base(args)` in the `bases` list).
3. **`payable(...)` cast and struct-literal construction** `S({x: 1})`.
   Both small.
4. **Interfaces + abstract contracts** as a third `ContractKind`.
5. **Anonymous events, indexed-arg expansion, struct-typed event params**.
6. **Typed locals** — extend `VarDeclStmt` with a type field so locals
   aren't always `uint256`. Requires symbol-table work (track locals by
   type) and updates throughout `visitUintExpr` / `visitBoolExpr`. Bigger
   than the rest of Tier 1; do it last in this tier.

### Tier 2 — large but high-value

7. **Inline assembly blocks**. The proto already has `protoToYul.cpp` —
   wire `InlineAssemblyStmt` to embed a generated Yul block as a string.
   Reuses existing Yul grammar.
8. **Low-level calls with `{value:, gas:}` options** — a new
   `LowLevelCallExpr` variant. Has to interact with the harness's
   status-comparison logic.
9. **Function-type values** — locals/params with function types,
   assignment, invocation.

### Tier 3 — defer

- Fixed-point general fuzzing (most paths unimplemented in solc anyway).
- NatSpec (no codegen impact).

## Validation methodology

After each tier, before merging:

1. Build both old and new fuzzer binaries.
2. Run with identical seed corpus and CPU budget (e.g. 1 h × 4 cores).
3. Measure:
   - Edge-coverage in `libsolidity/`
   - Edge-coverage in `libyul/` codegen
   - Compile-success rate
   - Differential-mismatch rate
   - Corpus size after run
4. Don't merge a tier if it shows net-negative edge-coverage delta.

## Risks to flag

- **Coverage drowning**: if much more code now exercises solc's
  *error-reporting* edges, those edges may dominate the coverage map and
  the fuzzer optimizes for diverse error messages instead of diverse
  codegen. Worth instrumenting before/after to detect.
- **Lost differential yield**: less compilable code = fewer EVM runs =
  fewer chances to catch optimizer mismatches per CPU-second. Tier 0
  shouldn't move this much; later tiers might.
- **Symbol-table explosion**: typed locals + multi-dim arrays + nested
  mappings each enlarge the per-function symbol bookkeeping. Watch for
  generation-time slowdown.
