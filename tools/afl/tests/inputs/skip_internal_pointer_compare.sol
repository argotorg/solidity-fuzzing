// Regression input: the legacy optimizer merges identical functions, so comparing internal function pointers
// differs (solc warning 3075).
contract C {
	function f() internal {}
	function g() internal {}
	function test() public pure returns (bool) {
		function () internal ptr = f;
		return ptr == g;
	}
}
