// Regression input: the reverse of viair_skip_init_order_derived_reads.sol, A's constructor reads B's immutable through a
// virtual call before legacy has initialized it.
abstract contract A {
	uint public t;
	constructor() { t = f(); }
	function f() virtual internal view returns (uint);
}
contract B is A {
	uint immutable x = 2;
	function f() override internal view returns (uint) { return x; }
}
