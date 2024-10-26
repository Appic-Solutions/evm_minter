// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "forge-std/Script.sol";
import "../src/Deposit.sol";

contract DeployDeposit is Script {
    Deposit public deposit;

    function run() public {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address minter_address = vm.envAddress("MINTER_ADDRESS");
        console.log("Deploying Deposit contract with address", vm.addr(pk));
        vm.startBroadcast(pk);
        _deployDeposit(minter_address);
        vm.stopBroadcast();
        console.log("Deposit contract deployed at address", address(deposit));
    }

    function _deployDeposit(address minter_address) internal {
        // Deploy the Deposit contract
        deposit = new Deposit(minter_address);
        console.log("Deposit contract initialized");
    }
}
