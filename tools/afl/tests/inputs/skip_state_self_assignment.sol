// Regression input: optimized code drops `x = x`, and with it the revert an SSTORE causes inside a STATICCALL, so
// fview() fails unoptimized and succeeds optimized. Found by a legacy_knobs campaign (2026-11-17).
contract C {
    uint256 x;
    function f() public returns (uint256) { x = x; return 1; }
}
interface CView {
    function f() external view returns (uint256);
}
contract D {
    function fview() public returns (uint256) { return CView(address(new C())).f(); }
}
