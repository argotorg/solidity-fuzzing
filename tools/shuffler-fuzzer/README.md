# Tools

## stackshuffler

Runs the SSA stack shuffler (`stack::shuffle`) on a `.stack` file and checks the result with the same
independent oracle as `shuffler_proto_ossfuzz` (`checkShuffle` in `StackShufflerTestCommon.h`).

```bash
make -C build -j$(nproc) stackshuffler
./build/tools/shuffler-fuzzer/stackshuffler --verbose path/to/test.stack   # trace table
./build/tools/shuffler-fuzzer/stackshuffler -                              # read stdin
```

Exit codes: 0 Admissible, 1 StackTooDeep, 2 bad input, 3 spec violation (printed as `VIOLATION:` lines).

### .stack file format

The target is positional, the same length as the final stack; `JUNK` positions accept anything.

```
// Comments start with //
initial: [v1, phi2, lit3, FunctionCallReturnLabel[0], ReturnLabel[0]]
target: [ReturnLabel[0], v1, v1, JUNK, lit5]
spilled: {phi2}          // optional: values already spilled (reloadable from memory)
allowSpilling: true      // optional, default true
reachableDepth: 16       // optional, 2..16
```

Slot tokens: `vN`, `phiN`, `litN`, `JUNK`, `ReturnLabel[N]`, `FunctionCallReturnLabel[N]`. Every target slot
must be on `initial`, spilled, or freely generatable (literal, junk, call return label).

The old `targetStackTop` / `targetStackTailSet` / `targetStackSize` format belonged to the shuffler upstream
removed in `0476499e9` and is rejected.
