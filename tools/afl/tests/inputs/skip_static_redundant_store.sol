// Regression input: `x &= x` inside a STATICCALLed function; optimized code drops the redundant store and with
// it the static-mode violation. Found by a legacy campaign (2026-11-18).
contract C {
    uint256 x;

    function f() public returns (uint256) {
        x &= y; assert(x == 127);
        return 1;
    }
}


interface CView {
    function f() external view returns (uint256);
}


interface CPure {
    function f() external pure returns (uint256);
}


contract D {
    function f() public returns (uint256) {
        return (new C()).f();
    }

    function fview() public returns (uint256) {
        return (CView(address(new C()))).f();
    }

    function fpure() public returns (uint256) {
        return (CPure(address(new C()))).f();
    }
}
// ====
// EVMVersion: >=byzantium
// ----
// f() -> 0x1 # This should work, next should throw #
// gas legacy: 76495
// gas legacy code: 25600
// fview() -> FAILURE
// gas irOptimized: 98425585
// gas irOptimized code: 13000
// gas legacy: 98413173
// gas legacy code: 25600
// gas legacyOptimized: 98425379
// gas legacyOptimized code: 13200
// gas ssaCFGOptimized: 98426960
// gas ssaCFGOptimized code: 11600
// fpure() -> FAILURE
// gas irOptimized: 98425585
// gas irOptimized code: 13000
// gas legacy: 98413173
// gas legacy code: 25600
// gas legacyOptimized: 98425379
// gas legacyOptimized code: 13200
// gas ssaCFGOptimized: 98426960
// gas ssaCFGOptimized code: 11600
