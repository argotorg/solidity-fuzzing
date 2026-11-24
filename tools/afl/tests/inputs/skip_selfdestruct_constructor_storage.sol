// Regression input: C's constructor stores an internal function pointer and self-destructs, leaving storage on an
// account without code (which EIP-6780 wipes at the end of the transaction) that the pointer masking cannot attribute
// to a layout. Found by a 7-day campaign (2026-11-24).
contract C {
    function() internal storedFn;
    constructor() {
        function() internal invalid;
        storedFn = invalid;
        selfdestruct(payable(msg.sender));
    }
}
contract Test {
    function f() public { new C(); }
}
