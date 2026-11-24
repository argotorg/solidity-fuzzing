// Regression input: f returns gasleft(), which differs between legacy and legacy-opt; the call graph reaches it, so
// the input is skipped.
contract C {
    function f() public view returns (uint) { return gasleft(); }
}
