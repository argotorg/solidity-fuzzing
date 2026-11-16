// Regression input: returns type(Empty).creationCode / runtimeCode, i.e. the compiled bytecode, which differs by
// optimiser/codegen config by design. These are compile-time constants, so the EVMHost EXTCODE* taint cannot see
// them; the runner skips such sources statically. Found by the viaIR-mode smoke campaign (2026-11-16).
contract Empty {}

contract C {
    function f() external returns (bytes memory, bytes memory){
        return (type(Empty).creationCode, type(Empty).runtimeCode);
    }
}
