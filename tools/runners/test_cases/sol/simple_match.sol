// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.0;

// Simple contract with no sub-deployments. Should match across all configs.
contract C {
    function test() public payable returns (uint256) {
        return 42;
    }
}
