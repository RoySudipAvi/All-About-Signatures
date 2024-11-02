// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {Verifier} from "src/Verifier.sol";
import {VeriferDeploy} from "script/Verifier.s.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract VerifierTest is Test {
    //using MessageHashUtils for bytes32;
    Verifier private s_verfier;
    address private s_address;
    uint256 private s_privateKey;
    function setUp() external {
        VeriferDeploy _deploy = new VeriferDeploy();
        s_verfier = _deploy.run();
        (s_address, s_privateKey) = makeAddrAndKey("alice");
    }

    function testPersonalSignVerification() external {
        string memory _message = "Hello!!! This is Alice";
        vm.startPrank(s_address);
        bytes32 hash = keccak256(abi.encodePacked(_message));
        (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(s_privateKey, hash);
        vm.stopPrank();
        address _signer = s_verfier.getSigner(_message, _v, _r, _s);
        console.log(s_address);
        console.log(_signer);
    }
}
