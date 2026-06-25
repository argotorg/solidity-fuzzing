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
./build/tools/shuffler-fuzzer/stackshuffler --verbose path/to/test.stack

# Just print status (exit 0 = Admissible, exit 1 = MaxIterationsReached)
./build/tools/shuffler-fuzzer/stackshuffler path/to/test.stack

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
