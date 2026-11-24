// Regression input: one operand increments an element of b, the other reads it. Found by a 7-day campaign
// (2026-11-24).
contract C {
    function f() public pure {
        uint[3] memory b = [uint(1), 2, 4];
        assert(++b[2] == b[2]);
    }
}
