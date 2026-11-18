// Regression input: one operand assigns z, the other reads it; legacy and IR evaluate the operands of a binary
// operation in different orders (the order is unspecified). Found by a viair campaign (2026-11-17).
contract C {
    function f(int256 x, int256 y) external pure returns (int256 z) {
        require((z = x + y) >= z);
    }
}
// ----
// f(int256,int256): 1, 2 -> 3
