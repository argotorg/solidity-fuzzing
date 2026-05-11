// Regression input: source contains the substring `gas()` (here inside
// a comment, see below), which must trip the harness's gas-call
// fast-path and exit 0 without running the differential. Gas
// observations legitimately differ between optimiser configurations,
// so any source mentioning gas() is treated as not interesting.
// Placed outside an `assembly` block so the existing assembly fast-path
// does not preempt this check.
//
//   gas()   <-- the substring being tested
//
contract C {
    function foo() public pure returns (uint256) { return 1; }
}
