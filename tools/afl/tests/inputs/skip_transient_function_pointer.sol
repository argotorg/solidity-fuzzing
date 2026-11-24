// Regression input: an internal function pointer in transient storage is a code offset in legacy and differs between
// legacy and legacy-opt; it is masked like one in storage. Found by a 7-day campaign (2026-11-24).
contract C {
    function() internal transient p;
    function g() internal {}
    function f() public { p = g; }
}
