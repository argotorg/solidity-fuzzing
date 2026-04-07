# Tools

## stackshuffler

Standalone tool for running the SSA stack shuffler on `.stack` test files. The
stack shuffler takes an initial EVM stack layout and target constraints, then
generates a sequence of EVM opcodes (SWAP, DUP, PUSH, POP) to reach an
admissible target layout.

### Building

```bash
cd build
cmake ..
make -j$(nproc) stackshuffler
```

### Usage

```bash
# Print the full trace table
./build/stackshuffler --verbose path/to/test.stack

# Just print status (exit 0 = Admissible, exit 1 = MaxIterationsReached)
./build/stackshuffler path/to/test.stack

# Read from stdin
echo "initial: [v1, v2]
targetStackTop: [v2, v1]" | ./build/stackshuffler --verbose -
```

### .stack file format

```
// Comments start with //
initial: [JUNK, v12, phi9, phi13, JUNK, JUNK, v65, v67]
targetStackTop: [lit27, phi13, phi9, v12, v67]
targetStackTailSet: {phi9, v12, phi13, v65}
targetStackSize: 21
```

**Fields:**

| Field | Required | Description |
|---|---|---|
| `initial` | yes | Initial stack layout, bottom to top |
| `targetStackTop` | yes | Required top portion of the target stack |
| `targetStackTailSet` | no | Set of values that must appear somewhere in the tail (below the top). Defaults to empty |
| `targetStackSize` | no | Total target stack size. Defaults to `len(targetStackTop)` if `targetStackTailSet` is empty |

**Slot types:**

- `v<N>` -- SSA variable (e.g. `v12`, `v67`)
- `phi<N>` -- phi node (e.g. `phi9`, `phi13`)
- `lit<N>` -- literal value (e.g. `lit27`)
- `JUNK` -- unused/don't-care slot

If the file contains a `// ----` delimiter (used by `isoltest` to separate expected output), everything after it is ignored.

### Output

With `--verbose`, the tool prints a trace table showing every opcode and the resulting stack state:

```
            |      0      1      2      3      4
            +-----------------------------------
   (initial)|      *      *      *     v1     v2
       SWAP1|      *      *      *     v2     v1
            +-----------------------------------
    (target)|      *      *      *     v2     v1
Status: Admissible
```

- `*` represents JUNK slots
- `|` separators mark boundaries between tail and args regions
- The `(target)` row shows the required layout: exact slots for the top (args)
  region, set notation `{...}` for tail requirements

Without `--verbose`, only the status line is printed.

### Existing test cases

The `solidity` submodule contains test cases at
`solidity/test/libyul/ssa/stackShuffler/*.stack`. Run them all:

```bash
for f in solidity/test/libyul/ssa/stackShuffler/*.stack; do
    echo -n "$(basename $f): "
    ./build/stackshuffler "$f"
done
```
