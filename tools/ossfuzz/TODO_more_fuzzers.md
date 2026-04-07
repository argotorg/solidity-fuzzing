# Additional Fuzzing Opportunities

Beyond the existing Yul and Solidity end-to-end (evmone) proto fuzzers, these are
areas worth fuzzing. Ordered by expected ROI.

## Priority 1: High-confidence targets with clear oracles

### 1. Individual Yul Optimizer Pass Fuzzing (IMPLEMENTED)

The existing fuzzers test the full optimizer suite. Individual passes should be
tested in isolation — each pass must preserve Yul semantics.

- Generate random Yul (reuse existing protobuf infra)
- Apply prerequisite passes (Disambiguator + `hgfo`) to both sides
- Run A = prerequisites only, Run B = prerequisites + single target pass
- Compile both → run on evmone → compare output, logs, storage

High-value passes to focus on:
- **SimplificationRules** — pattern-matching arithmetic rewrites, math-heavy = bug-prone
- **UnusedStoreEliminator** — removes stores it thinks are dead, silent data loss if wrong
- **LoadResolver** — resolves sload/mload via dataflow, data-flow bugs = miscompilation
- **LoopInvariantCodeMotion** — hoists code out of loops, classic source of compiler bugs
- **StackToMemoryMover** — moves variables to memory, changes semantics if wrong
- **CommonSubexpressionEliminator** — equivalence class tracking errors
- **FullInliner** — function inlining, scope/variable handling bugs

Binary: `yul_proto_ossfuzz_evmone_single_pass`, configured via `FUZZER_PASS` env var.

### 2. libevmasm Peephole Optimizer Differential

`libevmasm/PeepholeOptimiser.cpp` + `CommonSubexpressionEliminator.cpp` +
`BlockDeduplicator.cpp` operate on EVM assembly items (below Yul level). The
existing `const_opt_ossfuzz` only covers ConstantOptimiser.

Approach: generate Assembly items (from compiling random Yul), run with peephole
on vs off, compare evmone execution. Tests the lowest-level optimization layer.

### 3. AST JSON Round-trip

Solidity can export its AST as JSON (`--ast-compact-json`) and reimport it
(`ASTJsonImporter`). Both should produce identical bytecode:

```
source → parse → AST → JSON export → JSON import → AST' → compile → compare bytecode
```

No protobuf needed — any valid Solidity works. Tests JSON serialization of every
AST node type.

## Priority 2: Good targets with reasonable oracles

### 4. Standard JSON Interface Crash Fuzzing

`StandardCompiler::compile(string)` takes arbitrary JSON input. A crash-only
fuzzer (no oracle needed — just "don't crash/assert on any input") tests the
primary external-facing API. Malformed JSON, missing fields, wrong types, huge
inputs.

### 5. Solidity Parser Crash Fuzzing

`Parser::parse()` takes arbitrary `CharStream`. Crash-only fuzzer — feed random
bytes/strings, ensure no crashes or hangs. The parser has error recovery logic
exercised far less than the happy path. Complements existing proto fuzzers which
only generate *valid* Solidity.

### 6. SMTChecker Crash/Timeout Fuzzing

`ModelChecker::run()` triggers Z3/CVC5 queries. Feed valid Solidity with
`assert()` statements. Oracle: don't crash, don't hang (enforce timeout). The SMT
encoding is complex and less tested than the core compiler.

## Priority 3: Harder but potentially valuable

### 7. ABI Encoder/Decoder Round-trip

Generate a Solidity contract that ABI-encodes values, then ABI-decodes them, and
asserts equality. Compile and run on evmone. Tests ABI V2 encoder/decoder
consistency. Existing `protoToAbiV2.h/cpp` infrastructure partially supports this.

### 8. Source Map Consistency

After compilation, verify that every source map entry points to a valid byte range
in the original source. Purely structural validation, no execution needed.
