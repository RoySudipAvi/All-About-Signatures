// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script} from "forge-std/Script.sol";
import {Verifier} from "src/Verifier.sol";

contract VeriferDeploy is Script {
    Verifier private s_verifier;
    function run() external returns (Verifier) {
        vm.startBroadcast();
        s_verifier = new Verifier("EIP-191 Verification", "1.0");
        vm.stopBroadcast();
        return s_verifier;
    }
}
