// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.0;

// Deploys two different sub-contracts via CREATE2 with different salts.
// Exercises creation-order comparison with multiple deployed contracts.
contract A {
    uint256 public val;
    function set(uint256 _v) public { val = _v; }
}

contract B {
    uint256 public val;
    function set(uint256 _v) public { val = _v * 2; }
}

contract C {
    function test() public payable returns (uint256) {
        A a = new A{salt: bytes32(uint256(1))}();
        B b = new B{salt: bytes32(uint256(2))}();
        a.set(10);
        b.set(20);
        return a.val() + b.val();
    }
}
