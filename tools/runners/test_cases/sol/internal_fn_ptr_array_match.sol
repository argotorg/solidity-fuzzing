// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.0;

// Regression test for differential storage masking of internal function
// pointers held in dynamic storage arrays.
//
// An internal function pointer has no portable on-chain encoding: legacy
// codegen stores code offsets, via-IR stores sequential function IDs, and the
// offsets shift with the optimiser. A `function() internal[]` therefore lands
// at keccak256-derived data slots whose contents legitimately differ across
// every optimiser/codegen config. Without per-element masking of those slots
// the differential runner reports a spurious storage mismatch (exit 1); with
// it, all configs must compare equal (exit 0).
//
// `externalArr` is included on purpose: external function pointers (address +
// selector) ARE portable, must NOT be masked, and must still compare equal.
contract C {
    function f1() public {}
    function f2() public {}
    function f3() public {}

    function() internal[] internalArr;
    function() internal[] internalArrDefault;
    function() external[] externalArr;

    constructor() {
        internalArr = [f1, f2, f3];
        internalArrDefault = new function() internal[](3);
        externalArr = [this.f1, this.f2, this.f3];
    }

    // The differential runner calls test(); the interesting storage writes
    // already happened in the constructor.
    function test() public payable returns (uint256) {
        return internalArr.length + internalArrDefault.length + externalArr.length;
    }
}
