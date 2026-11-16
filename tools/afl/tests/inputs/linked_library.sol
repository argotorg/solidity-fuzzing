// Regression input: a public library function, called through DELEGATECALL once the runner deploys and links the
// library; the call must succeed and agree across configs.
library L {
    function twice(uint x) public pure returns (uint) { return 2 * x; }
}
contract C {
    function f(uint x) external pure returns (uint) { return L.twice(x); }
}
// ----
// f(uint256): 21 -> 42
