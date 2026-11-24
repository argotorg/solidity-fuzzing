// Regression input: a library helper forwards gas() from inline assembly, but nothing calls it, so the input is
// compared rather than skipped (and must not differ).
library L {
    function send(address to) internal returns (bool ok) {
        assembly { ok := call(gas(), to, 0, 0, 0, 0, 0) }
    }
    function twice(uint x) internal pure returns (uint) { return 2 * x; }
}
contract C {
    function f(uint x) public pure returns (uint) { return L.twice(x); }
}
