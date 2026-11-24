// Regression input: one operand increments a parenthesized x, the other reads it; legacy and IR evaluate the operands
// in different orders. Found by a 7-day campaign (2026-11-24).
contract C {
    uint x;
    function f() public returns (bool) { return x == ++(x); }
}
