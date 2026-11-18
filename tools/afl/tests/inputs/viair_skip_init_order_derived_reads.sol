// Regression input: via-IR runs all state variable initializers before any constructor, legacy runs B's after
// A's constructor, so y is 42 vs 0 (docs/ir-breaking-changes.rst). Found by the 2026-11-16 validation campaign.
contract A {
	uint x;
	constructor() { x = 42; }
	function f() public view returns (uint) { return x; }
}
contract B is A {
	uint public y = f();
}
