// Regression input: IR always uses ABI coder v2, whose decoder rejects the dirty int8 that v1 lets through. Found
// by a viair campaign (2026-11-18).
pragma abicoder "v1";


contract C {
    function f(int8 a, uint8 b) public returns (int8) {
        return a >> b;
    }
}
// ----
// f(int8,uint8): 0x99, 0x00 -> FAILURE

// f(int8,uint8): 0x99, 0x02 -> FAILURE
// f(int8,uint8): 0x99, 0x04 -> FAILURE
// f(int8,uint8): 0x99, 0x08 -> FAILURE
