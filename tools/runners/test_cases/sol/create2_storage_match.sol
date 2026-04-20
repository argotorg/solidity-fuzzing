// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.0;

// Sub-contract deployed via CREATE2. Different bytecodes across configs produce
// different CREATE2 addresses, but storage VALUES should match. This exercises
// the creation-order-based storage comparison.
contract C0 {
    uint256[] public sv0_0;

    function f0_0(uint256 p0, uint256 p1) public pure virtual returns (uint256) {
        return 0;
    }

    function f0_1(uint256 p0, uint256 p1) public virtual returns (uint256) {
        for (uint256 i0 = 0; i0 < 3; i0++) {
            sv0_0.push();
        }
        return 0;
    }

    function f0_2(uint256 p0, uint256 p1) public virtual returns (uint256) {
        for (uint256 i0 = 0; i0 < 3; i0++) {
            sv0_0.push();
        }
        return 0;
    }

}

contract C {
    function _cdl(uint256 _o) private pure returns (uint256 _v) {
        assembly { _v := calldataload(_o) }
    }
    function test() public payable returns (uint256) {
        uint256 _r = 0;
        try new C0{salt: bytes32(uint256(0x000000007265766572745f6572726f725f343262333039300000000000000000) ^ 0)}() returns (C0 _tC0) {
            (bool _s0, bytes memory _d0) = address(_tC0).call(abi.encodeWithSignature("f0_0(uint256,uint256)", _cdl(4), _cdl(36)));
            if (_s0 && _d0.length == 32) _r ^= abi.decode(_d0, (uint256));
            (bool _ss1, bytes memory _sd1) = address(_tC0).staticcall(abi.encodeWithSignature("f0_0(uint256,uint256)", _cdl(68), _cdl(100)));
            if (_ss1 && _sd1.length == 32) _r ^= abi.decode(_sd1, (uint256));
            (bool _s2, bytes memory _d2) = address(_tC0).call(abi.encodeWithSignature("f0_1(uint256,uint256)", _cdl(132), _cdl(164)));
            if (_s2 && _d2.length == 32) _r ^= abi.decode(_d2, (uint256));
            (bool _ds3, bytes memory _dd3) = address(_tC0).delegatecall(abi.encodeWithSignature("f0_1(uint256,uint256)", _cdl(196), _cdl(228)));
            if (_ds3 && _dd3.length == 32) _r ^= abi.decode(_dd3, (uint256));
            (bool _s4, bytes memory _d4) = address(_tC0).call(abi.encodeWithSignature("f0_2(uint256,uint256)", _cdl(260), _cdl(292)));
            if (_s4 && _d4.length == 32) _r ^= abi.decode(_d4, (uint256));
        } catch {}
        return _r;
    }
}
