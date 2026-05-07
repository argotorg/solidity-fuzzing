// Regression input: contract reads its own deployed bytecode via
// extcodecopy(address(), ...) and returns part of it. The deployed
// bytecode legitimately differs across optimiser/codegen settings, so
// the differential output check would fire — a harness false positive.
// EVMHost::m_readsDeployedCode must trip and the runner must skip
// (exit 0). Originally surfaced by the AFL fuzzer (sec4/id:000008).
contract C { fallback() external { assembly {
    extcodecopy(address(), 1, 0, 67434)
    return (0, 0x80)
}}}
