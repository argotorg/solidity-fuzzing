// Regression input: the CREATE2 address depends on the config's init code. Normalizing it needs the creation order
// recorded during deployment, which EVMHost used to clear at each transaction boundary.
contract C {}
contract D {
	C c;
	bytes32 h;
	constructor() { c = new C{salt: "abc"}(); }
	function f() public returns (C) { h = address(c).codehash; return c; }
}
