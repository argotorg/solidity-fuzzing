// Regression input: any source containing the substring `assembly`
// must trip the harness's inline-asm fast-path and exit 0 without
// running the differential. Inline-asm blocks regularly produce code
// that violates solc's documented guarantees in ways the differential
// oracle mistakes for optimiser mismatches, so they are skipped wholesale.
contract C {
    fallback() external {
        assembly {
            sstore(0, 1)
        }
    }
}
