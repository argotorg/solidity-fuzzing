// Regression input: a base constructor argument writes a state variable that has an initializer; legacy and IR
// order the two differently. Found by a viair campaign (2026-11-18).
contract A {
    uint public x = 2;
    constructor(uint) {}
    function f() public returns(uint) { x = 4; }
}
contract B is A {
    constructor() A(f()) {}
}
// ----
// x() -> 4
