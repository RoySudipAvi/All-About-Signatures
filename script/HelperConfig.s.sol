//SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script} from "forge-std/Script.sol";

contract HelperConfig {
    struct Config {
        address deployer;
    }

    address public constant LOCAL_DEPLOYER =
        0x976EA74026E726554dB657fA54763abd0C3a0aa9;
    address public constant BASE_SEPOLIA_DEPLOYER =
        0xCc51a734Fd91A26058F55C9BC083450E0c7D5Fcf;
    uint256 public constant LOCAL_CHAIN_ID = 31337;
    uint256 public constant BASE_SEPOLIA_CHAIN_ID = 84532;
    mapping(uint256 chainId => Config) private s_chaindIdConfig;

    constructor() {
        if (block.chainid == LOCAL_CHAIN_ID) {
            getLocalConfig();
        } else {
            getBaseSepoliaConfig();
        }
    }

    function getBaseSepoliaConfig() public returns (Config memory config) {
        config = Config(BASE_SEPOLIA_DEPLOYER);
        s_chaindIdConfig[block.chainid] = config;
    }

    function getLocalConfig() public returns (Config memory config) {
        config = Config(LOCAL_DEPLOYER);
        s_chaindIdConfig[block.chainid] = config;
    }

    function getConfigByChainId() external view returns (Config memory) {
        return s_chaindIdConfig[block.chainid];
    }
}
