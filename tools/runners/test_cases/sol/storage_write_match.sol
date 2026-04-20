// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.0;

// Contract that writes to storage slots. No sub-deployments.
// Tests basic storage comparison across optimization configs.
contract C {
    uint256 public counter;
    mapping(uint256 => uint256) public data;

    function test() public payable returns (uint256) {
        counter = 7;
        data[0] = 100;
        data[1] = 200;
        data[2] = 300;
        return counter;
    }
}
