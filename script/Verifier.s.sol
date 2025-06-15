// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script} from "forge-std/Script.sol";
import {Verifier} from "src/Verifier.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract VeriferDeploy is Script {
    Verifier private s_verifier;
    function run() external returns (Verifier) {
        HelperConfig helper = new HelperConfig();
        HelperConfig.Config memory config = helper.getConfigByChainId();
        vm.startBroadcast(config.deployer);
        s_verifier = new Verifier("Demo Signatures", "1.0");
        vm.stopBroadcast();
        return s_verifier;
    }
}
