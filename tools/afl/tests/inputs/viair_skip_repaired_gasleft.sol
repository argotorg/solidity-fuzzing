// Regression input: undeclared-identifier repair turns `gassert` into the gas builtin. Found by a viair campaign
// (2026-11-18).
contract D {
    uint public x;
    constructor(function() external pure returns (uint) g) {
        x = gassert();
    }
}

contract C {
    function f() public returns (uint r) {
        D d = new D(this.sixteen);
        r = d.x();
    }

    function sixteen() public pure returns (uint) {
        return 16;
    }
}
// ====
// ----
// f() -> 16
// gas legacy: 78477
// gas legacy code: 23600
