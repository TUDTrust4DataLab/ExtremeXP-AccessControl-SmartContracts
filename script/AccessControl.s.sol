// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/PAP.sol";
import "../src/PDP.sol";
import "../src/Ideko.sol";
import "../src/I2cat.sol";
import "../src/Cs.sol";
import "../src/Moby.sol";
import "../src/Airbus.sol";

contract DeployAccessControl is Script {
    function run() external {
        vm.startBroadcast();

        // 1. Deploy Use Case Contracts
        Ideko ideko = new Ideko();
        I2cat i2cat = new I2cat();
        CS cs = new CS();
        Moby moby = new Moby();
        Airbus airbus = new Airbus();

        console.log("Ideko deployed at:", address(ideko));
        console.log("I2cat deployed at:", address(i2cat));
        console.log("CS deployed at:", address(cs));
        console.log("Moby deployed at:", address(moby));
        console.log("Airbus deployed at:", address(airbus));

        // 2. Deploy PAP with static use case addresses
        string[] memory names = new string[](5);
        address[] memory contracts = new address[](5);

        names[0] = "Ideko";
        contracts[0] = address(ideko);

        names[1] = "I2cat";
        contracts[1] = address(i2cat);

        names[2] = "Cs";
        contracts[2] = address(cs);

        names[3] = "Moby";
        contracts[3] = address(moby);

        names[4] = "Airbus";
        contracts[4] = address(airbus);

        PAP pap = new PAP(names, contracts);
        console.log("PAP deployed at:", address(pap));

        // 3. Deploy PDP and set it in PAP
        PDP pdp = new PDP(address(pap));
        console.log("PDP deployed at:", address(pdp));

        pap.setPDP(address(pdp));

       

        vm.stopBroadcast();
    }
}
