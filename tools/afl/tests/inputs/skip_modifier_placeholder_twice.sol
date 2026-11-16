// Regression input: via-IR resets return variables on each `_` (docs/ir-breaking-changes.rst), so f(true) is 1
// vs 2.
contract C {
	modifier repeat(bool twice) { if (twice) _; _; }
	function f(bool twice) public repeat(twice) returns (uint r) { r += 1; }
}
// ----
// f(bool): true -> 1
