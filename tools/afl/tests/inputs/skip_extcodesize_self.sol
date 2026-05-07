// Regression input: contract uses extcodesize(address()) as part of an
// sstore key. The triple-XOR-with-1 obfuscation reduces to
// xor(extcodesize, 1), so the slot is extcodesize(self)+1. Optimised vs
// non-optimised builds have different runtime sizes, so they sstore to
// different slots — harness false positive, not a real differential.
// EVMHost::m_readsDeployedCode must trip and the runner must skip
// (exit 0). Originally surfaced by the AFL fuzzer (sec8/id:000016).
contract C { fallback() external { assembly {
    let h := 0x42
    sstore(add(xor(xor(xor(extcodesize(address()),1),1),1), 1), h)
}}}
